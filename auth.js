import { supabase } from './supabaseClient.js'

/**
 * 회원가입 함수
 */
export async function signUp(email, password) {
  try {
    const { data, error } = await supabase.auth.signUp({
      email: email,
      password: password,
    })

    if (error) throw error
    return { success: true, data }
  } catch (error) {
    console.error('회원가입 에러:', error.message)
    return { success: false, error: error.message }
  }
}

/**
 * 로그인 함수
 */
export async function signIn(email, password) {
  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email: email,
      password: password,
    })

    if (error) throw error
    return { success: true, data }
  } catch (error) {
    console.error('로그인 에러:', error.message)
    return { success: false, error: error.message }
  }
}
