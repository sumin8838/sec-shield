import { supabase } from './supabaseClient.js'

const resetBtn = document.getElementById('reset-btn')

resetBtn.addEventListener('click', async () => {
  const newPassword = document.getElementById('new-password').value.trim()

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

  alert('비밀번호가 변경되었습니다.')

  location.href = './popup.html'
})
