
import { NextResponse } from "next/server";
import { randomBytes } from "node:crypto";

export async function GET(request) {
  const clientId = process.env.GITHUB_CLIENT_ID;

  if (!clientId) {
    return NextResponse.json(
      { success: false, message: "Missing GitHub Client ID" },
      { status: 500 }
    );
  }

  const state = randomBytes(32).toString("hex");

  const redirectUri = new URL(
    "/api/auth/github/callback",
    request.url
  ).toString();

  const githubUrl = new URL(
    "https://github.com/login/oauth/authorize"
  );

  githubUrl.searchParams.set("client_id", clientId);
  githubUrl.searchParams.set("redirect_uri", redirectUri);
  githubUrl.searchParams.set("scope", "read:user user:email");
  githubUrl.searchParams.set("state", state);

  const response = NextResponse.redirect(githubUrl);

  response.cookies.set("github_oauth_state", state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 600,
  });

  return response;
}
