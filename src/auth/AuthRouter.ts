import { Router } from 'express';
import { AuthController } from './AuthController';
import passport from 'passport';
import { authenticatedMiddleware } from '../middleware/authMiddleware';
import {User} from "@prisma/client";
import OAuth2Strategy, {StrategyOptions, VerifyCallback, VerifyFunction} from 'passport-oauth2';
import {prisma} from "../prismaClient";

const AuthRouter = Router();
const authController = new AuthController();

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser<User>(function (user, done) {
  done(null, user);
});

const isAllowedToRegister = (organizations: string[]) => {
  const allowedOrgs = (process.env.ALLOWED_ORGS ?? '')
    .split(',')
    .filter(org => org !== '')

  if (allowedOrgs.length <= 0) return true
  console.log(organizations, allowedOrgs)
  return !!organizations.find(organization => {
    return allowedOrgs.find(allowedOrg => allowedOrg === organization)
  })
}

type GithubStrategyOptions = StrategyOptions & {
  userAgent?: string
  userProfileURL?: string
  userEmailURL?: string
  userOrgsURL?: string
}

class Strategy extends OAuth2Strategy {
  private _userProfileURL: string;
  private _userEmailURL: string;
  private _userOrgsURL: string;
  constructor(options: GithubStrategyOptions, verify: VerifyFunction) {
    options.authorizationURL =
        options.authorizationURL ?? 'https://github.com/login/oauth/authorize';
    options.tokenURL =
        options.tokenURL ?? 'https://github.com/login/oauth/access_token';
    options.scopeSeparator = options.scopeSeparator || ',';
    options.customHeaders = options.customHeaders || {};

    if (!options.customHeaders['User-Agent']) {
      options.customHeaders['User-Agent'] =
          options.userAgent || 'passport-github';
    }

    super(options, verify);

    this._userProfileURL =
        options.userProfileURL || 'https://api.github.com/user';
    this._userEmailURL =
        options.userEmailURL || 'https://api.github.com/user/emails';
    this._userOrgsURL = options.userOrgsURL || 'https://api.github.com/user/orgs';
    this._oauth2.useAuthorizationHeaderforGET(true)
    this.name = 'github'
  }

  getUser(accessToken: string){
    return new Promise((resolve, reject) => {
      this._oauth2.get(this._userProfileURL, accessToken, (err: any, body: any) => {
        if (err) return reject(err);
        resolve(JSON.parse(body));
      });
    });
  }
  getEmails(accessToken: string){
    return new Promise((resolve, reject) => {
      this._oauth2.get(this._userEmailURL, accessToken, (err: any, body: any) => {
        if (err) return reject(err);
        resolve(JSON.parse(body));
      });
    });
  }

  getOrganizations(accessToken: string){
    return new Promise((resolve, reject) => {
      this._oauth2.get(this._userOrgsURL, accessToken, (err: any, body: any) => {
        if (err) return reject(err);
        resolve(JSON.parse(body));
      });
    });
  }

  async userProfile(accessToken: string, done: (err?: (Error | null), profile?: any) => void) {
    try {
      const user: any = await this.getUser(accessToken) ;
      const emails: any = await this.getEmails(accessToken);
      const organizations: any = await this.getOrganizations(accessToken);

      done(null, {
        id: user.id,
        githubNickname: user.login,
        email: emails.find((email: any) => email.primary === true).email,
        organizations: organizations.map((org: any) => org.login),
        avatar: user.avatar_url,
      });
    } catch (e: any){
      done(e, null);
    }
  }

}

const strategy = new Strategy({
  authorizationURL: 'https://github.com/login/oauth/authorize',
  tokenURL: 'https://github.com/login/oauth/access_token',
  clientID: process.env.GITHUB_CLIENT_ID as string,
  clientSecret: process.env.GITHUB_CLIENT_SECRET as string,
  callbackURL: process.env.GITHUB_CALLBACK_URL as string,
  customHeaders: {
    'User-Agent': 'passport-github'
  }
}, verifyUser)

export async function verifyUser(accessToken: string, refreshToken: string, profile: any, verified: VerifyCallback) {
  if (!isAllowedToRegister(profile.organizations ?? [])) {
    verified(new Error('Invalid organization'), undefined);
    return;
  }

  try {
    const user = await prisma.user.upsert({
      where: { email: profile.email },
      create: {
        email: profile.email,
        githubNickname: profile.githubNickname,
        avatar: profile.avatar,
      },
      update: {
        email: profile.email,
        githubNickname: profile.githubNickname,
        avatar: profile.avatar,
      },
    });
    verified(null, user);
  } catch (e: any) {
    verified(e, undefined);
  }
}

passport.use(strategy)

AuthRouter.get(
  '/auth/github',
  passport.authenticate('oauth2', { scope: ['user:email', 'read:org'] }),
);

AuthRouter.get(
  '/auth/github/callback',
  passport.authenticate('oauth2', {
    failureRedirect: '/login',
    failureFlash: false,
  }),
  authController.callback,
);

AuthRouter.get('/auth/me', [authenticatedMiddleware, authController.me]);

export { AuthRouter };
