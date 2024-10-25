import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";

const isProtectedRoute = createRouteMatcher(["/dashboard(.*)", "/name(.*)"]);


export default clerkMiddleware((auth, req) => {
});

export const config = {
  matcher: ["/((?!.*\\..*|_next).*)", "/"],
  
};