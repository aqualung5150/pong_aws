import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtGuard extends AuthGuard('jwt') {}

// @Injectable()
// export class JwtGuard implements CanActivate {
//     constructor(private jwtService: JwtService) {}

//     async canActivate(context: ExecutionContext): Promise<boolean> {
//         const request = context.switchToHttp().getRequest();

//         // use token in header
//         // const token = this.extractTokenFromHeader(request);

//         // use token in cookie
//         const token = request.cookies['access_token'];

//         if (!token) {
//             throw new UnauthorizedException();
//         }
//         try {
//             const payload = await this.jwtService.verifyAsync(
//                 token,
//                 {
//                     secret: jwtConstants.secret
//                 }
//             );
//             request['user'] = payload;
//         } catch {
//             throw new UnauthorizedException();
//         }
//         return true;
//     }

//     // use token in header
//     // private extractTokenFromHeader(request: Request): string | undefined {
//     //     const [type, token] = request.headers.authorization?.split(' ') ?? [];
//     //     return type === 'Bearer' ? token : undefined;
//     // }
// }