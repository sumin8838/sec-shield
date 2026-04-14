/**
 * reuse.js
 * 비밀번호 재사용 탐지 및 장기 사용 탐지 로직
 * storage.js와 utils.js(PwUtils.sha1Hex)에 의존합니다.
 */

const LONG_USE_THRESHOLD_DAYS = 90

async function analyzeReuse(password, currentDomain) {
  // 빈 비밀번호 또는 빈 도메인은 분석하지 않음
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

  // utils.js의 PwUtils.sha1Hex 사용
  const hash = await window.PwUtils.sha1Hex(password)

  const reuseInfo = await checkReuse(hash, currentDomain)
  const daysOnSite = await getDaysUsedOnSite(hash, currentDomain)

  await recordHash(hash, currentDomain)

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
