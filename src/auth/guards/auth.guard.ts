import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { AuthService } from '../auth.service';
import { identity } from 'rxjs';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService:JwtService,
    private auhtService: AuthService,
  ){}
  async canActivate(
    context: ExecutionContext,
  ):  Promise<boolean>  {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request)
  
    if(!token){
      throw new UnauthorizedException('There is no bearer Token');
    }
    try{
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token, {secret: process.env.JWT_SEED,}//valida que el token recibido este generado con mi propia llave
      );
      const user = await this.auhtService.findUserById(payload.id);
      if(!user) throw new UnauthorizedException('User does no exists');
      if(!user.isActive) throw new UnauthorizedException('User is not active');
      request['user'] = user;
      return Promise.resolve(true);

    }catch (error){
      throw new UnauthorizedException();
    }
    return true;
  }
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
