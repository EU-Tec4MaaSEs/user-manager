# tec4maases-user-manager

## Overview

User manager is responsible to handle authentication process inside Tec4MaaSEs. It connects with Keycloak and routes all requests to authenticate
users, refresh tokens, manage users and their roles and request information regarding their authorization in the system.

It exploits OAuth2.0 and OpenID protocols integrated with Spring Security with configured Request Filters to increase the security of the application and generate JWT Tokens for users. It utilizes Keycloak libraries to connect directly with Keycloak resource server.

Utilizes and implements the following concepts:
    - Spring Security with OpenID and JWT Tokens
    - Async Programming
    - Spring Events to initialize variables at the app initialization

## Table of Contents

1. [Installation](#installation)
2. [Usage](#usage)
3. [Deployment](#deployment)
4. [License](#license)
5. [Contributors](#contributors)

### Installation

1. Clone the repository:

    ```sh
    git clone https://[username]@bitbucket.org/atc-code/ilab-tec4maases-user-manager.git
    cd ilab-tec4maases-user-manager
    ```

2. Install the dependencies:

    ```sh
    mvn install
    ```

3. Instantiate an instance of Keycloak with PostgresSQL and configure the following variables:

   ```sh
   server.port=${APP_PORT:8094}
   application.url=${APP_URL:http://localhost:8094}
   keycloak.url=${KEYCLOAK_URL:###}
   keycloak.realm=${KEYCLOAK_REALM:###}
   keycloak.client-id=${KEYCLOAK_CLIENT_ID:###}
   keycloak.client-secret=${KEYCLOAK_CLIENT_SECRET:###}
   keycloak.admin-username=${KEYCLOAK_ADMIN_USERNAME:###}
   keycloak.admin-password=${KEYCLOAK_ADMIN_PASSWORD:###}
   spring.security.cors.domains=${CORS_DOMAINS:http://localhost:3000}
   spring.mail.host = ${MAIL_HOST:smtp.gmail.com}
   spring.mail.port = ${MAIL_PORT:587}
   spring.mail.username = ${MAIL_USERNAME:tec4maases}
   spring.mail.password = ${MAIL_APP_PASSWORD:###}
   app.frontend.url = ${APP_FRONTEND_URL:http://localhost:3000}
   ```

4. If needed you can upload the ```realm_export.json``` configuration provided in the repository to configure Keycloak automatically.

### Usage

1. Run the application after Keycloak (Utilized version 16.1.1) is deployed:

    ```sh
    mvn spring-boot:run
    ```

2. The application will start on `http://localhost:8094`.

3. Access the OpenAPI documentation at `http://localhost:8094/api/user-manager/swagger-ui/index.html`.

### Deployment

For local deployment Docker containers can be utilized to deploy the microservice with the following procedure:

1. Ensure Docker is installed and running.

2. Build the maven project:

    ```sh
    mvn package
    ```

3. Build the Docker container:

    ```sh
    docker build -t tec4maases-user-manager:latest .
    ```

4. Run the Docker container including the environmental variables:

    ```sh
    docker run -d -p 8094:8094 --name tec4maases-user-manager tec4maases-user-manager:latest
    ```

   ``NOTE``: The following environmental variable should be configured:

   ```sh
    APP_PORT=..
    APP_URL=..
    KEYCLOAK_URL=..
    KEYCLOAK_REALM=..
    KEYCLOAK_CLIENT_ID=..
    KEYCLOAK_CLIENT_SECRET=..
    CORS_DOMAINS=..
    MAIL_HOST=..
    MAIL_PORT=..
    MAIL_USERNAME=..
    MAIL_APP_PASSWORD=..
    APP_FRONTEND_URL=..
   ```

5. To stop container run:

    ```sh
    docker stop tec4maases-user-manager
    ```

6. To deploy Keycloak with PostgreSQL just execute via Docker the following command in the project directory:

    ```sh
    docker compose up -d
    ```

## License

TThis project has received funding from the European Union's Horizon 2022 research and innovation programm, under Grant Agreement 101091996.

For more details about the licence, see the [LICENSE](LICENSE) file.

## Contributors

- Alkis Aznavouridis (<a.aznavouridis@atc.gr>)
