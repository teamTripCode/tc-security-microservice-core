import { NestFactory } from '@nestjs/core';
import { SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { swaggerConfig, swaggerOptions } from 'src/swagger.config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS if needed
  app.enableCors();

  // Global validation pipe
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }));

  // Swagger configuration
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api', app, document, swaggerOptions);

  await app.listen(process.env.PORT ?? 3000);

  console.log(`🚀 Application is running on: ${await app.getUrl()}`);
  console.log(`📚 Swagger documentation available at: ${await app.getUrl()}/api`);
}

bootstrap();