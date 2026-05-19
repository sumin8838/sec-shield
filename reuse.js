/**
 * reuse.js
 * 비밀번호 재사용 탐지 및 장기 사용 탐지 로직
 * background.js에 메시지를 보내 Supabase DB와 통신합니다.
 */

const LONG_USE_THRESHOLD_DAYS = 90

async function analyzeReuse(password, currentDomain) {
  if (!password || password.length < 1 || !currentDomain) {
    return {
      isReused: false,
      isLongUsed: false,
      otherSites: [],
      reuseCount: 0,
      daysSinceFirst: 0,
      daysOnSite: 0,
    }
  }

  const hash = await window.PwUtils.sha1Hex(password)

  // background.js에 메시지로 요청
  const reuseInfo = await chrome.runtime.sendMessage({
    action: 'checkReuse',
    payload: { hash, domain: currentDomain },
  })

  const daysOnSite = await chrome.runtime.sendMessage({
    action: 'getDaysUsedOnSite',
    payload: { hash, domain: currentDomain },
  })

  // 기록 저장
  await chrome.runtime.sendMessage({
    action: 'recordHash',
    payload: { hash, domain: currentDomain },
  })

  const isLongUsed = daysOnSite >= LONG_USE_THRESHOLD_DAYS

  return {
    isReused: reuseInfo.isReused,
    isLongUsed,
    otherSites: reuseInfo.otherSites,
    reuseCount: reuseInfo.reuseCount,
    daysSinceFirst: reuseInfo.daysSinceFirst,
    daysOnSite,
  }
}

function buildReuseMessages(reuseResult) {
  const warnings = []
  const details = []
  const allSites = reuseResult.otherSites || []

  if (reuseResult.isReused) {
    warnings.push('다른 사이트에서도 동일한 비밀번호를 사용 중입니다.')
    details.push(`재사용된 사이트 수: ${allSites.length}개`)
    details.push(`재사용 횟수: ${reuseResult.reuseCount}회`)
  }

  if (reuseResult.isLongUsed) {
    warnings.push(
      `이 사이트에서 ${reuseResult.daysOnSite}일째 동일한 비밀번호를 사용 중입니다.`,
    )
    details.push('보안을 위해 주기적인 비밀번호 변경을 권장합니다.')
  }

  return { warnings, details, allSites }
}

window.analyzeReuse = analyzeReuse
window.buildReuseMessages = buildReuseMessages