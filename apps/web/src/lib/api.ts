import API from './axios-client'
import { LoginDto } from '@gainometer/base-ts-interfaces'

export const loginMutationFn = async (data: LoginDto) =>
  await API.post('/auth/login', data)
