window.PwAnalyzer = (() => {
  function evaluatePassword(password, options = {}) {
    const {
      siteName = '',
      reused = false,
      similarReused = false,
      leaked = false,
    } = options

    let score = 0
    const warnings = []
    const passed = []

    if (!password) {
      return {
        score: 0,
        status: '입력 대기',
        statusClass: 'waiting',
        warnings: ['비밀번호 입력 시 분석이 시작됩니다.'],
        passed: [],
      }
    }

    if (password.length < 8) {
      warnings.push('길이가 너무 짧습니다.')
    } else if (password.length < 12) {
      score += 20
      warnings.push('12자 이상을 권장합니다.')
    } else {
      score += 30
      passed.push('길이가 충분합니다.')
    }

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

    if (reused) {
      score -= 20
      warnings.push('다른 사이트에서 동일한 비밀번호를 재사용 중입니다.')
    }

    if (similarReused) {
      score -= 10
      warnings.push('다른 사이트에서 유사한 비밀번호를 반복 사용 중입니다.')
    }

    if (leaked) {
      score -= 30
      warnings.push('유출 이력이 있는 비밀번호 입니다.')
    }

    if (score < 0) score = 0
    if (score > 100) score = 100

    let status = '위험'
    let statusClass = 'danger'

    if (score >= 80) {
      status = '안전'
      statusClass = 'safe'
    } else if (score >= 50) {
      status = '보통'
      statusClass = 'normal'
    }

    return {
      score,
      status,
      statusClass,
      warnings,
      passed,
    }
  }

  return {
    evaluatePassword,
  }
})()
