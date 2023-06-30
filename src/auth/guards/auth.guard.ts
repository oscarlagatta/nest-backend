import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { AuthService } from "../auth.service";
import { JwtPayload } from "../interfaces/jwt-payload";


@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private readonly jwtService: JwtService,
    private authService: AuthService
    ) {}
  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean>  {

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    console.log({token});

    if (!token) {
      throw new UnauthorizedException('No bearer token found');
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token,
        {
          secret: process.env.JWT_SEED
        }
      );
      // console.log({payload});
      const user = await this.authService.findUserById(payload.id)

      if (!user) throw new UnauthorizedException('user does not exist');
      if (!user.isActive) throw new UnauthorizedException('user is not active');

      request['user'] = user;

    } catch {
      throw new UnauthorizedException();
    }

    return true;
  }

  private extractTokenFromHeader(request: Request):string | undefined {
    const [type, token]= request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
