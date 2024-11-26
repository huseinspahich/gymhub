# Node.js Web API with JWT Authentication and Authorization
This repository provides the source code for a Node.js Web API implementing JWT-based authentication and authorization. The implementation utilizes Express.js as the foundation for a fast and scalable web server, and PostgreSQL for persistent data storage.

## Key Features
- **Registration**
Users can register a new user account by providing the required data (email and password). If the email is already in use, the system will notify the user.

- **Authentication**
Users can authenticate themselves using their usernames (email) and passwords. Upon successful authentication, an access token and refresh token are generated:
    - Access token: This token grants access to protected resources and is returned in the response body.      
    - Refresh token: This token allows the user to refresh the access token without going through the authentication process again. It is securely stored in an HttpOnly cookie.    
- **Authorization**
The API supports defining different roles and permissions for users. Currently, the API checks if the logged-in user has the required email (only admin has access to the protected route). This feature enables fine-grained control over access to various parts of the application.

- **Refresh Token Rotation**
To enhance security, the API implements a refresh token rotation mechanism:
     - After each request to refresh the access token, a new refresh token is generated.
     - This minimizes the exposure time to potential threats, as the old refresh token is invalidated after each use.
- **Protected Routes**
Certain routes (e.g., /protected) are protected and require the user to be authenticated. Access is granted only if the user’s email matches the authorized email.

## Technologies Used
- **Node.js**: JavaScript runtime for building the server-side application.   
- **Express.js**: Web framework for building the API and handling routing.  
- **JWT (JSON Web Tokens)**: Used for secure authentication and authorization.   
- **PostgreSQL**: Database for storing user information.    
- **Passport.js**: Authentication middleware for handling local and Google OAuth strategies.    
- **bcrypt**: For password hashing and secure authentication.   
- **cookie**: For handling cookies, including HttpOnly cookies to store refresh tokens.  
- **dotenv**: For environment variable management.  
