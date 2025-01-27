// Note: The middleware always runs whenever the URL changes, page refreshes or before the page is rendered

import { NextRequest, NextResponse } from 'next/server'

// Routes that require authentication
const protectedRoutes = ['/home', '/sessions']

// Routes that are accessible without authentication
const publicRoutes = [
  '/',
  '/signup',
  '/confirm-account',
  'forgot-password',
  'reset-password',
  '/verify-mfa',
]

export default async function middleware(req: NextRequest) {
  /* 
  Since this middleware runs on every URL change or page refresh, we get the current URL and check if it's a protected route or public route and then based on whether 
  the user is authenticated or not (checking the access token in the cookies), we redirect them to the appropriate page.
  */
  // Get the current path from the request URL
  const path = req.nextUrl.pathname
  const isProtectedRoute = protectedRoutes.includes(path)
  const isPublicRoute = publicRoutes.includes(path)

  // Get the access token from cookies
  const accessToken = req.cookies.get('accessToken')?.value

  // Redirect to home page if trying to access protected route without authentication
  if (isProtectedRoute && !accessToken) {
    return NextResponse.redirect(new URL('/', req.nextUrl))
  }

  // Redirect to home if trying to access public route while authenticated
  if (isPublicRoute && accessToken) {
    return NextResponse.redirect(new URL('/home', req.nextUrl))
  }

  // Continue with the request
  return NextResponse.next()
}
