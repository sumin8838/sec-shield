import { supabase } from './supabaseClient.js'

/* ─────────────────────────────────────────
  DOM 요소
───────────────────────────────────────── */
const emailInput = document.getElementById('email')
const passwordInput = document.getElementById('password')

const loginBtn = document.getElementById('login-btn')
const logoutBtn = document.getElementById('logout-btn')
const resendBtn = document.getElementById('resend-btn')

const authSection = document.getElementById('auth-section')
const successSection = document.getElementById('success-section')

// [추가] OTP 인증 관련 새 DOM 요소
const otpSection = document.getElementById('otp-section')
const otpCodeInput = document.getElementById('otp-code')
const otpConfirmBtn = document.getElementById('otp-confirm-btn')

const userEmail = document.getElementById('user-email')
const statusMsg = document.getElementById('status-msg')

/* ================================
  [추가] 비밀번호 변경 DOM 요소
================================ */
const newPasswordInput = document.getElementById('new-password')

const changePasswordBtn = document.getElementById('change-password-btn')

/* ─────────────────────────────────────────
  상태 메시지 출력
───────────────────────────────────────── */
function showStatus(msg, isError = false) {
  statusMsg.innerHTML = msg

  statusMsg.style.color = isError ? '#f55' : '#4f8ef7'
}

/* ─────────────────────────────────────────
  로그인 성공 화면
───────────────────────────────────────── */
function showSuccess(session) {
  authSection.style.display = 'none'

  successSection.style.display = 'block'

  userEmail.textContent = session.user.email

  showStatus('')
}

/* ─────────────────────────────────────────
  로그인 화면
───────────────────────────────────────── */
function showLogin() {
  authSection.style.display = 'block'

  successSection.style.display = 'none'

  resendBtn.style.display = 'none'

  // [추가] 로그인 화면 진입 시 OTP 섹션 숨김 및 입력값 초기화
  otpSection.style.display = 'none'
  otpCodeInput.value = ''

  showStatus('')
}

/* ─────────────────────────────────────────
  팝업 열릴 때 세션 확인
───────────────────────────────────────── */
chrome.storage.local.get(['session'], (result) => {
  if (result.session) {
    showSuccess(result.session)
  } else {
    showLogin()
  }
})

/* ─────────────────────────────────────────
  로그인
───────────────────────────────────────── */
loginBtn.addEventListener('click', async () => {
  const email = emailInput.value.trim()

  const password = passwordInput.value.trim()

  /* 입력값 체크 */
  if (!email || !password) {
    return showStatus('이메일과 비밀번호를 입력해주세요.', true)
  }

  resendBtn.style.display = 'none'

  showStatus('로그인 중...')

  /* Supabase 로그인 */
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  })

  /* 로그인 실패 */
  if (error) {
    console.error(error)

    /* 이메일 존재 여부 확인 */
    const { data: existingUser } = await supabase
      .from('profiles')
      .select('email')
      .eq('email', email)
      .maybeSingle()

    /* 이메일 존재 */
    if (existingUser) {
      return showStatus('비밀번호가 올바르지 않습니다.', true)
    }

    /* 이메일 없음 */
    return showStatus(
      `
        계정이 존재하지 않습니다.
        <br><br>

        <a
          href="#"
          id="create-account"
          style="
            color:#10b981;
            text-decoration:none;
            font-weight:600;
          "
        >
          회원가입하기
        </a>
        `,
      true,
    )
  }

  /* 이메일 인증 여부 검증 */
  if (!data.user || !data.user.email_confirmed_at) {
    await supabase.auth.signOut()

    resendBtn.style.display = 'block'

    resendBtn.dataset.email = email

    // [추가] 아직 미인증 상태인 경우 가입 이메일을 바인딩하고 OTP 입력 UI를 활성화
    otpSection.style.display = 'block'
    otpConfirmBtn.dataset.email = email

    return showStatus(
      `
        이메일 인증이 필요합니다.
        <br>
        발송된 6자리 인증번호를 입력하거나 메일함을 확인해주세요.
        `,
      true,
    )
  }

  /* 로그인 성공 */
  chrome.storage.local.set({ session: data.session }, () => {
    showSuccess(data.session)
  })
})

/* ─────────────────────────────────────────
  회원가입 링크 클릭
───────────────────────────────────────── */
document.addEventListener('click', async (e) => {
  if (e.target.id === 'create-account') {
    e.preventDefault()

    const email = emailInput.value.trim()

    const password = passwordInput.value.trim()

    /* 입력값 체크 */
    if (!email || !password) {
      return showStatus('이메일과 비밀번호를 입력해주세요.', true)
    }

    /* 비밀번호 길이 */
    if (password.length < 6) {
      return showStatus('비밀번호는 6자 이상이어야 합니다.', true)
    }

    resendBtn.style.display = 'none'

    showStatus('회원가입 중...')

    /* 회원가입 요청 -> Supabase 백엔드 설정에 따라 6자리 OTP 자동 메일 전송 */
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    })

    /* 회원가입 실패 */
    if (error) {
      console.error(error)

      return showStatus(error.message, true)
    }

    /* profiles 저장 */
    if (data.user) {
      const { error: insertError } = await supabase.from('profiles').insert({
        id: data.user.id,
        email: email,
      })

      if (insertError) {
        console.error(insertError)
      }
    }

    // [추가] 가입 성공 시 OTP 입력을 위한 화면 제어 및 이메일 바인딩
    otpSection.style.display = 'block'
    otpConfirmBtn.dataset.email = email

    resendBtn.style.display = 'block'

    resendBtn.dataset.email = email

    showStatus(
      `
        ✉️ 인증번호 6자리를 발송했습니다.
        <br>
        5분 내로 인증번호를 입력하고 [인증 완료]를 눌러주세요.
        `,
    )
  }
})

/* ─────────────────────────────────────────
  [추가] 6자리 OTP 인증번호 백엔드 검증 로직 
───────────────────────────────────────── */
otpConfirmBtn.addEventListener('click', async () => {
  const email = otpConfirmBtn.dataset.email
  const token = otpCodeInput.value.trim()

  if (!token || token.length !== 6) {
    return showStatus('올바른 6자리 인증번호를 입력해주세요.', true)
  }

  showStatus('인증 확인 중...')

  // Supabase 백엔드 서버로 사용자가 입력한 토큰 검증 요청
  const { data, error } = await supabase.auth.verifyOtp({
    email,
    token,
    type: 'signup',
  })

  if (error) {
    console.error(error)
    return showStatus(`인증 실패: ${error.message}`, true)
  }

  // 검증 성공 시 로그인 처리
  if (data.session) {
    chrome.storage.local.set({ session: data.session }, () => {
      otpSection.style.display = 'none'
      otpCodeInput.value = ''
      showSuccess(data.session)
    })
  }
})

/* ─────────────────────────────────────────
  인증 메일 재전송
───────────────────────────────────────── */
resendBtn.addEventListener('click', async () => {
  const email = resendBtn.dataset.email || emailInput.value.trim()

  if (!email) {
    return showStatus('이메일을 입력해주세요.', true)
  }

  showStatus('재전송 중...')

  const { error } = await supabase.auth.resend({
    type: 'signup',
    email: email,
  })

  if (error) {
    return showStatus(error.message, true)
  }

  showStatus(
    `
      ✉️ 인증번호를 재전송했습니다.
      <br>
      메일함을 다시 확인해주세요.
      `,
  )
})

/* ─────────────────────────────────────────
  로그아웃
───────────────────────────────────────── */
logoutBtn.addEventListener('click', async () => {
  await supabase.auth.signOut()

  chrome.storage.local.remove(['session'], () => {
    showLogin()
  })
})

/* ─────────────────────────────────────────
  비밀번호 변경 기능
───────────────────────────────────────── */
if (changePasswordBtn) {
  changePasswordBtn.addEventListener('click', async () => {
    const newPassword = newPasswordInput.value.trim()

    if (!newPassword) {
      return alert('새 비밀번호를 입력해주세요.')
    }

    // Auth 비밀번호 변경
    const { error } = await supabase.auth.updateUser({
      password: newPassword,
    })

    if (error) {
      console.error(error)
      return alert(error.message)
    }

    // 현재 로그인 유저 가져오기
    const {
      data: { user },
    } = await supabase.auth.getUser()

    // DB 비밀번호 업데이트
    const { error: dbError } = await supabase
      .from('profiles')
      .update({
        password: newPassword,
      })
      .eq('id', user.id)

    if (dbError) {
      console.error(dbError)
      return alert('DB 업데이트 실패')
    }

    alert('비밀번호가 변경되었습니다.')

    newPasswordInput.value = ''
  })
}

/* ─────────────────────────────────────────
  비밀번호 재설정 메일 발송
───────────────────────────────────────── */
document.addEventListener('click', async (e) => {
  if (e.target.id === 'forgot-password') {
    e.preventDefault()

    const email = emailInput.value.trim()

    if (!email) {
      return showStatus('비밀번호를 찾을 이메일을 입력해주세요.', true)
    }

    showStatus('비밀번호 재설정 메일 전송 중...')

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: 'http://localhost:5500/reset-password.html',
    })

    if (error) {
      console.error(error)

      return showStatus(error.message, true)
    }

    showStatus(
      `
        ✉️ 비밀번호 재설정 메일을 전송했습니다.
        <br>
        이메일을 확인해주세요.
      `,
    )
  }
})
