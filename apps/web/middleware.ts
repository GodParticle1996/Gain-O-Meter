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

  try {
    // Redirect to login if trying to access protected route without authentication
    if (isProtectedRoute && !accessToken) {
      return NextResponse.redirect(new URL('/', req.nextUrl))
    }

    // Redirect to home if trying to access public route while authenticated
    if (isPublicRoute && accessToken) {
      return NextResponse.redirect(new URL('/home', req.nextUrl))
    }

    // Continue with the request
    return NextResponse.next()
  } catch (error) {
    // Handle any errors and redirect to login
    console.error('Middleware error:', error)
    return NextResponse.redirect(new URL('/', req.nextUrl))
  }
}

/* 
Question: Given that I already have a custom Axios response interceptor in place to handle automatic renewal of access tokens using 
refresh tokens, what is the purpose of implementing a Next.js middleware in this setup? Specifically, I am trying to 
understand the flow of data between the frontend and backend, and how the middleware interacts with the Axios interceptor.

To test this, I deleted the access token from the browser's cookies and navigated to a protected route like /home. However, 
the middleware logic designed to redirect users when an access token is missing never executed, even though the access token 
was absent.

Also explain that whether the Next middleware gets called first or the axios response interceptor? If the axios response 
interceptor is getting called first for a protected route lets say /home without the accessToken, ten it will get a new 
accessToken using the refreshToken and then if the Next middleware is getting called, then since I already have the 
accessToken in the cookie, it will never execute:

if (isProtectedRoute && !accessToken) {
  return NextResponse.redirect(new URL('/', req.nextUrl))
}

Answer: Order of Execution:
The Next.js middleware runs first on initial page loads or route changes
The Axios response interceptor runs only for API requests (not for page routes)

Flow for Protected Route (/home) Without accessToken:
User navigates to /home
  Next.js middleware runs:
    Checks for accessToken in cookies
    Finds no accessToken
    Redirects to / (login page)
This happens before any frontend code executes

  Axios Response Interceptor Flow:
    The response interceptor only runs for API requests (not for page routes)
    If an API request fails with 401 Unauthorized:
    Interceptor catches the error
    Tries to renew accessToken using refreshToken
    If successful, updates cookies and retries request
    If failed, redirects to login

Why the middleware might not trigger:
  The middleware runs on server-side route changes, not on client-side state changes
*/
