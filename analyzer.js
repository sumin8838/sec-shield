window.PwAnalyzer = (() => {
  /**
   * 비밀번호 강도를 평가하고 점수/상태/경고를 반환합니다.
   *
   * @param {string} password
   * @param {{
   *   siteName?: string,
   *   reuseCount?: number,
   *   leaked?: boolean
   * }} options
   * @returns {{ score: number, status: string, statusClass: string, warnings: string[], passed: string[] }}
   */
  function evaluatePassword(password, options = {}) {
    const {
      siteName = '',
      reuseCount = 0, // 다른 사이트 재사용 횟수 (0이면 +10점, 5~9이면 +5점, 10+이면 +0점)
      leaked = false, // 유출 비밀번호 여부 (향후 유출 검사 기능 연동용)
    } = options

    let score = 0
    const warnings = []
    const passed = []

    // ── 빈 입력 ───────────────────────────────────────────────
    if (!password) {
      return {
        score: 0,
        status: '입력 대기',
        statusClass: 'waiting',
        warnings: ['비밀번호 입력 시 분석이 시작됩니다.'],
        passed: [],
      }
    }

    // ── 길이 (최대 30점) ──────────────────────────────────────
    if (password.length < 8) {
      warnings.push('길이가 너무 짧습니다.')
    } else if (password.length < 12) {
      score += 20
      warnings.push('12자 이상을 권장합니다.')
    } else {
      score += 30
      passed.push('길이가 충분합니다.')
    }

    // ── 문자 조합 (각 15점, 최대 60점) ───────────────────────
    if (/[A-Z]/.test(password)) {
      score += 15
      passed.push('대문자 포함')
    } else {
      warnings.push('대문자가 없습니다.')
    }

    if (/[a-z]/.test(password)) {
      score += 15
      passed.push('소문자 포함')
    } else {
      warnings.push('소문자가 없습니다.')
    }

    if (/[0-9]/.test(password)) {
      score += 15
      passed.push('숫자 포함')
    } else {
      warnings.push('숫자가 없습니다.')
    }

    if (/[^A-Za-z0-9]/.test(password)) {
      score += 15
      passed.push('특수문자 포함')
    } else {
      warnings.push('특수문자가 없습니다.')
    }

    // ── 재사용 횟수 (최대 10점) ───────────────────────────────
    if (reuseCount < 5) {
      score += 10
      passed.push('비밀번호 재사용 없음 (+10점)')
    } else if (reuseCount < 10) {
      score += 5
      warnings.push(
        `비밀번호를 ${reuseCount}개 사이트에서 재사용 중입니다. (+5점)`,
      )
    } else {
      warnings.push(
        `비밀번호를 ${reuseCount}개 이상 사이트에서 재사용 중입니다. (+0점)`,
      )
    }

    // ── 감점 항목 ─────────────────────────────────────────────
    if (/(.)\1\1/.test(password)) {
      score -= 10
      warnings.push('같은 문자가 3번 이상 반복됩니다.')
    }

    if (/123|abc|qwe|password|admin|1111|0000/i.test(password)) {
      score -= 15
      warnings.push('너무 쉬운 패턴이 포함되어 있습니다.')
    }

    if (siteName && password.toLowerCase().includes(siteName.toLowerCase())) {
      score -= 10
      warnings.push('사이트명과 비슷한 문자열이 포함되어 있습니다.')
    }

    if (leaked) {
      score -= 30
      warnings.push('유출 이력이 있는 비밀번호입니다.')
    }

    // ── 범위 보정 ─────────────────────────────────────────────
    score = Math.max(0, Math.min(100, score))

    // ── 상태 판정 ─────────────────────────────────────────────
    let status = '위험'
    let statusClass = 'danger'

    if (score >= 80) {
      status = '안전'
      statusClass = 'safe'
    } else if (score >= 50) {
      status = '보통'
      statusClass = 'normal'
    }

    return { score, status, statusClass, warnings, passed }
  }

  return { evaluatePassword }
})()