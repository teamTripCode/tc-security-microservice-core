import { DocumentBuilder } from '@nestjs/swagger';

export const swaggerConfig = new DocumentBuilder()
    .setTitle('Security Microservice API')
    .setDescription(`
    # Security Microservice API

    This microservice provides comprehensive authentication and authorization functionality.

    ## Features
    - User registration and login
    - JWT token management (access & refresh tokens)
    - Password reset functionality
    - Token validation and blacklisting
    - Role-based access control

    ## Authentication
    Most endpoints require authentication via JWT tokens. Use the **Authorize** button to set your bearer token.

    ## Getting Started
    1. Register a new user account using the \`/auth/register\` endpoint
    2. Login with your credentials using the \`/auth/login\` endpoint
    3. Use the received access token to authenticate subsequent requests
    4. Use the refresh token to obtain new access tokens when they expire

    ## Token Management
    - Access tokens expire in 15 minutes
    - Refresh tokens expire in 7 days
    - Tokens can be blacklisted via the logout endpoint
    - Use the validate endpoint to check token validity

    ## Error Handling
    The API uses standard HTTP status codes:
    - 200: Success
    - 201: Created
    - 204: No Content
    - 400: Bad Request
    - 401: Unauthorized
    - 409: Conflict
    - 500: Internal Server Error
  `)
    .setVersion('1.0.0')
    .setContact(
        'API Support',
        'https://yourcompany.com/support',
        'support@yourcompany.com'
    )
    .setLicense('MIT', 'https://opensource.org/licenses/MIT')
    .addTag('Authentication', 'User authentication and authorization endpoints')
    .addTag('Health Check', 'Service health monitoring endpoints')
    .addBearerAuth(
        {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            name: 'JWT',
            description: 'Enter JWT token',
            in: 'header',
        },
        'JWT-auth',
    )
    .addServer('http://localhost:3000', 'Development server')
    .addServer('https://api.yourdomain.com', 'Production server')
    .build();

export const swaggerOptions = {
    customSiteTitle: 'Security Microservice API Documentation',
    customfavIcon: 'https://nestjs.com/img/logo_text.svg',
    customCss: `
    .swagger-ui .topbar { display: none }
    .swagger-ui .info { margin: 50px 0 }
    .swagger-ui .info .title { color: #e53e3e }
    .swagger-ui .scheme-container { 
      background: #f7fafc; 
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 16px;
      margin: 16px 0;
    }
  `,
    swaggerOptions: {
        persistAuthorization: true,
        tagsSorter: 'alpha',
        operationsSorter: 'alpha',
        docExpansion: 'none',
        filter: true,
        showRequestHeaders: true,
        showCommonExtensions: true,
    },
};