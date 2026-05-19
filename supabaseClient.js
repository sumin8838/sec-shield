import { createClient } from './supabase-bundle.js'

const SUPABASE_URL = 'https://wccoqnnzcyueokxufbhj.supabase.co'
const SUPABASE_ANON_KEY = 'sb_publishable_wWDN3L3XOSWAwZiN_RouBQ_jgKs-khP'

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
