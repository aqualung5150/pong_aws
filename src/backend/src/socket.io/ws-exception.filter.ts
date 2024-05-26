import { ArgumentsHost, Catch, ExceptionFilter, HttpException, Logger } from '@nestjs/common';
import { WsException } from '@nestjs/websockets';

@Catch(WsException, HttpException)
export class WsExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(WsExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost) {
    const payload = host.switchToWs().getData();
    this.logger.error(`${exception.name} - invalid data transfer: ${payload}`);
    // console.log(`${exception.name} - invalid data transfer: ${payload}`);
  }
}