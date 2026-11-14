
import { NextResponse } from "next/server";
import { connectDB } from "../../../../../lib/db.js";
import User from "../../../../../models/User.js";
import { SignJWT } from "jose";

export async function GET(request) {
  const storedState =
    request.cookies.get("github_oauth_state")?.value;

  const clearStateCookie = (response) => {
    response.cookies.set("github_oauth_state", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 0,
    });

    return response;
  };

  try {
    const { searchParams } = new URL(request.url);

    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const returnedError = searchParams.get("error");

    if (returnedError) {
      return clearStateCookie(
        NextResponse.json(
          {
            success: false,
            message: "GitHub authorization was denied",
          },
          { status: 400 }
        )
      );
    }

    if (!code || !state || !storedState || state !== storedState) {
      return clearStateCookie(
        NextResponse.json(
          {
            success: false,
            message: "Invalid OAuth state or missing code",
          },
          { status: 400 }
        )
      );
    }

    const redirectUri = new URL(
      "/api/auth/github/callback",
      request.url
    ).toString();

    // Exchange authorization code for access token
    const tokenResponse = await fetch(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client_id: process.env.GITHUB_CLIENT_ID,
          client_secret: process.env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: redirectUri,
        }),
        cache: "no-store",
      }
    );

    const tokenData = await tokenResponse.json();

    if (
      !tokenResponse.ok ||
      tokenData.error ||
      !tokenData.access_token
    ) {
      throw new Error("GitHub token exchange failed");
    }

    const githubHeaders = {
      Authorization: `Bearer ${tokenData.access_token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    };

    // Fetch GitHub profile
    const githubResponse = await fetch(
      "https://api.github.com/user",
      {
        headers: githubHeaders,
        cache: "no-store",
      }
    );

    if (!githubResponse.ok) {
      throw new Error("Failed to fetch GitHub profile");
    }

    const githubUser = await githubResponse.json();

    // Fetch verified primary email if profile email is private
    let email = githubUser.email;

    if (!email) {
      const emailResponse = await fetch(
        "https://api.github.com/user/emails",
        {
          headers: githubHeaders,
          cache: "no-store",
        }
      );

      if (emailResponse.ok) {
        const emails = await emailResponse.json();

        email =
          emails.find(
            (item) => item.primary && item.verified
          )?.email ?? null;
      }
    }

    // Save user in MongoDB
    await connectDB();

    const user = await User.findOneAndUpdate(
      { githubId: String(githubUser.id) },
      {
        $set: {
          username: githubUser.login,
          name: githubUser.name,
          email,
          avatarUrl: githubUser.avatar_url,
          bio: githubUser.bio,
          lastLoginAt: new Date(),
        },
      },
      {
        new: true,
        upsert: true,
        setDefaultsOnInsert: true,
      }
    );

    // Create signed session
    const sessionSecret = process.env.SESSION_SECRET;

    if (!sessionSecret || Buffer.byteLength(sessionSecret) < 32) {
      throw new Error("SESSION_SECRET must be at least 32 bytes");
    }

    const secret = new TextEncoder().encode(sessionSecret);

    const session = await new SignJWT({
      userId: user._id.toString(),
      githubId: user.githubId,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("7d")
      .sign(secret);

    const response = NextResponse.redirect(
      new URL("/", request.url)
    );

    response.cookies.set("prlens_session", session, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    });

    return clearStateCookie(response);
  } catch (error) {
    console.error("GitHub OAuth callback failed:", error);

    return clearStateCookie(
      NextResponse.json(
        {
          success: false,
          message: "GitHub authentication failed",
        },
        { status: 500 }
      )
    );
  }
}
