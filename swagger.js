const swaggerJsdoc = require('swagger-jsdoc');
const swaggerDocs = require('./swaggerDocs'); // Import the documentation module
const fs = require('fs');

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API Documentation',
      version: '1.0.0',
      description: 'Centralized documentation for API endpoints.',
    },
    servers: [
      {
        url: 'https://comp4537databaseserver-ahgghrarabaxhyec.westus-01.azurewebsites.net', // Replace with your base URL
      },
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    paths: swaggerDocs.paths, // Inject paths from the separate documentation module
  },
  apis: [], // No need to point to controllers, since paths are manually included
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Save Swagger specification to a JSON file
fs.writeFileSync('./swagger.json', JSON.stringify(swaggerSpec, null, 2));

console.log('Swagger specification generated successfully!');
