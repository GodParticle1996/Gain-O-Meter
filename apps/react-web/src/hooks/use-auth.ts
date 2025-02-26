'use client'

import { useQuery } from '@tanstack/react-query'
import { getUserSessionQueryFn } from '@/lib/api'

const useAuth = () => {
  const query = useQuery({
    queryKey: ['authUser'],
    queryFn: getUserSessionQueryFn,
    staleTime: Infinity,
    retry: 0, // Disable automatic retries by react-query
    refetchOnWindowFocus: false, // Prevent refetching on focus
  })
  return query
}

export default useAuth
