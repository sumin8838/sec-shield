/**
 * storage.js
 * chrome.storage.local 기반 비밀번호 해시 기록 관리 모듈
 * 원문 비밀번호는 절대 저장하지 않으며, 해시값만 사용합니다.
 */

const STORAGE_KEY = 'pwguard_records'
const STORAGE_VERSION_KEY = 'pwguard_version'
const CURRENT_VERSION = 2 // 버전이 다르면 저장소 자동 초기화
const RECORD_EXPIRE_DAYS = 180

// ─── 내부 헬퍼 ──────────────────────────────────────────────────────────────

function isStorageAvailable() {
  return !!(chrome && chrome.storage && chrome.storage.local)
}

/**
 * 호스트명에서 루트 도메인을 추출합니다.
 * nid.naver.com → naver / accounts.google.com → google
 * @param {string} host
 * @returns {string}
 */
function normalizeHostToDomain(host) {
  if (!host) return ''
  const parts = host.replace(/^www\./, '').split('.')
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0]
}

/**
 * 잘못 저장된 서브도메인 기록을 루트 도메인으로 자동 교정합니다.
 * 예: nid → naver, accounts → google
 * 같은 루트 도메인으로 합쳐지는 항목은 first_seen/last_seen을 병합합니다.
 * @param {Object} records
 * @returns {{ records: Object, changed: boolean }}
 */
function migrateDomains(records) {
  const KNOWN_FIXES = {
    nid: 'naver',
    accounts: 'google',
    signin: 'google',
    login: 'kakao',
    auth: 'kakao',
  }

  let changed = false
  const migrated = {}

  for (const [hash, record] of Object.entries(records)) {
    const normalizedSites = []

    for (const site of record.sites) {
      const fixedDomain = KNOWN_FIXES[site.domain] || site.domain
      if (fixedDomain !== site.domain) changed = true

      // 같은 루트 도메인이 이미 있으면 병합
      const existing = normalizedSites.find((s) => s.domain === fixedDomain)
      if (existing) {
        existing.first_seen = Math.min(existing.first_seen, site.first_seen)
        existing.last_seen = Math.max(existing.last_seen, site.last_seen)
        changed = true
      } else {
        normalizedSites.push({ ...site, domain: fixedDomain })
      }
    }

    migrated[hash] = {
      ...record,
      sites: normalizedSites,
      reuse_count: Math.max(0, normalizedSites.length - 1),
    }
  }

  return { records: migrated, changed }
}

/**
 * 오래된 도메인 항목을 정리합니다.
 * last_seen이 180일 이상 지난 항목 제거, 남은 항목이 없는 해시는 전체 삭제.
 * @param {Object} records
 * @returns {Object}
 */
function purgeExpiredEntries(records) {
  const now = Date.now()
  const expireMs = RECORD_EXPIRE_DAYS * 24 * 60 * 60 * 1000
  const cleaned = {}

  for (const [hash, record] of Object.entries(records)) {
    const activeSites = record.sites.filter((s) => now - s.last_seen < expireMs)
    if (activeSites.length === 0) continue
    cleaned[hash] = {
      ...record,
      sites: activeSites,
      reuse_count: Math.max(0, activeSites.length - 1),
    }
  }

  return cleaned
}

// ─── 공개 함수 ──────────────────────────────────────────────────────────────

/**
 * 저장된 전체 기록을 가져옵니다.
 * 최초 로드 시 잘못된 도메인이 있으면 자동으로 교정 후 저장합니다.
 * @returns {Promise<Object>}
 */
async function getAllRecords() {
  if (!isStorageAvailable()) return {}

  return new Promise((resolve) => {
    chrome.storage.local.get(
      [STORAGE_KEY, STORAGE_VERSION_KEY],
      async (result) => {
        if (chrome.runtime.lastError) {
          console.warn(
            '[PwGuard] storage read error:',
            chrome.runtime.lastError.message,
          )
          resolve({})
          return
        }

        const savedVersion = result[STORAGE_VERSION_KEY] || 0

        // 버전이 다르면 저장소 초기화 후 현재 버전으로 업데이트
        if (savedVersion !== CURRENT_VERSION) {
          console.log(
            `[PwGuard] 저장소 버전 업데이트 (v${savedVersion} → v${CURRENT_VERSION}), 기록 초기화`,
          )
          chrome.storage.local.set({
            [STORAGE_KEY]: {},
            [STORAGE_VERSION_KEY]: CURRENT_VERSION,
          })
          resolve({})
          return
        }

        let records = result[STORAGE_KEY] || {}

        // 잘못된 도메인 자동 교정 (변경이 있을 때만 저장)
        const { records: migrated, changed } = migrateDomains(records)
        if (changed) {
          records = migrated
          chrome.storage.local.set({ [STORAGE_KEY]: records }, () => {
            if (chrome.runtime.lastError) {
              console.warn(
                '[PwGuard] migration save error:',
                chrome.runtime.lastError.message,
              )
            }
          })
        }

        resolve(records)
      },
    )
  })
}

/**
 * 전체 기록을 저장합니다.
 * @param {Object} records
 * @returns {Promise<void>}
 */
async function saveAllRecords(records) {
  if (!isStorageAvailable()) return

  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEY]: records }, () => {
      if (chrome.runtime.lastError) {
        console.warn(
          '[PwGuard] storage write error:',
          chrome.runtime.lastError.message,
        )
      }
      resolve()
    })
  })
}

/**
 * 비밀번호 해시와 현재 도메인을 기록합니다.
 * 도메인은 루트 도메인으로 정규화하여 저장합니다.
 * @param {string} hash
 * @param {string} domain - 이미 정규화된 루트 도메인
 * @returns {Promise<void>}
 */
async function recordHash(hash, domain) {
  if (!hash || !domain) return

  let records = await getAllRecords()

  // 20% 확률로 만료 항목 정리 (매번 실행 시 부하 방지)
  if (Math.random() < 0.2) {
    records = purgeExpiredEntries(records)
  }

  const now = Date.now()

  if (!records[hash]) {
    records[hash] = {
      sites: [{ domain, first_seen: now, last_seen: now }],
      reuse_count: 0,
    }
  } else {
    const siteEntry = records[hash].sites.find((s) => s.domain === domain)
    if (siteEntry) {
      siteEntry.last_seen = now
    } else {
      records[hash].sites.push({ domain, first_seen: now, last_seen: now })
      records[hash].reuse_count = (records[hash].reuse_count || 0) + 1
    }
  }

  await saveAllRecords(records)
}

/**
 * 특정 해시의 기록을 조회합니다.
 * @param {string} hash
 * @returns {Promise<Object|null>}
 */
async function getRecord(hash) {
  if (!hash) return null
  const records = await getAllRecords()
  return records[hash] || null
}

/**
 * 특정 해시가 현재 도메인 외 다른 곳에서도 사용됐는지 확인합니다.
 * @param {string} hash
 * @param {string} currentDomain
 * @returns {Promise<{ isReused: boolean, otherSites: string[], reuseCount: number, daysSinceFirst: number }>}
 */
async function checkReuse(hash, currentDomain) {
  const record = await getRecord(hash)

  if (!record) {
    return {
      isReused: false,
      otherSites: [],
      reuseCount: 0,
      daysSinceFirst: 0,
    }
  }

  const otherSites = record.sites
    .filter((s) => s.domain !== currentDomain)
    .map((s) => s.domain)

  const allFirstSeen = record.sites.map((s) => s.first_seen)
  const earliest = Math.min(...allFirstSeen)
  const daysSinceFirst = Math.floor(
    (Date.now() - earliest) / (1000 * 60 * 60 * 24),
  )

  return {
    isReused: otherSites.length > 0,
    otherSites,
    reuseCount: otherSites.length,
    daysSinceFirst,
  }
}

/**
 * 현재 도메인에서 동일 해시를 사용한 기간(일수)을 반환합니다.
 * @param {string} hash
 * @param {string} currentDomain
 * @returns {Promise<number>}
 */
async function getDaysUsedOnSite(hash, currentDomain) {
  const record = await getRecord(hash)
  if (!record) return 0

  const siteEntry = record.sites.find((s) => s.domain === currentDomain)
  if (!siteEntry) return 0

  return Math.floor((Date.now() - siteEntry.first_seen) / (1000 * 60 * 60 * 24))
}
