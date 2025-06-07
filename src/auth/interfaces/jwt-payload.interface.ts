export interface JwtPayload {
  sub: string; // user_id
  email: string;
  roles: string[];
  permissions: string[];
  iat?: number;
  exp?: number;
}