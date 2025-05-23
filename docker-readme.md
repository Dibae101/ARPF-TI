# Running ARPF-TI with Docker Compose on Ubuntu

This guide provides instructions on how to build and run the ARPF-TI application using Docker Compose on an Ubuntu machine. Docker Compose simplifies the management of multi-container Docker applications.

**Note:** This setup includes the SQLite database (`db.sqlite3`) directly within the Docker image. Changes to the database will require rebuilding the image to persist.

## Prerequisites

1.  **Ubuntu Machine:** A server or desktop running a recent version of Ubuntu (e.g., 20.04 LTS or later).
2.  **Docker:** Docker must be installed. Follow the official Docker installation guide for Ubuntu: [Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
3.  **Docker Compose:** Docker Compose must be installed. Follow the official installation guide: [Install Docker Compose](https://docs.docker.com/compose/install/)
4.  **Git:** Git must be installed to clone the repository (`sudo apt update && sudo apt install git`).

## Steps

### 1. Clone the Repository

Open your terminal on the Ubuntu machine and clone the project repository:

```bash
git clone <repository-url> # Replace <repository-url> with the actual URL
cd ARPF-TI
```

### 2. Configure Environment Variables

The application requires several environment variables for configuration, especially secrets.

1.  **Copy the Example:** Create your own environment file from the example provided:
    ```bash
    cp .env.example .env
    ```

2.  **Edit `.env`:** Open the `.env` file with a text editor (like `nano` or `vim`) and fill in the required values:
    ```bash
    nano .env
    ```
    **Crucial Settings:**
    *   `DJANGO_SECRET_KEY`: **Generate a new, strong, unique secret key.** You can use Python: `python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'`
    *   `DJANGO_DEBUG`: Set this to `False` for production/testing.
    *   `DJANGO_ALLOWED_HOSTS`: Enter the IP address(es) or domain name(s) that will be used to access the application, separated by commas (e.g., `your_server_ip,your_domain.com`).
    *   Update email settings (`SMTP_...`) if you need alert emails.
    *   Add any necessary API keys (`API_KEY`, etc.).

    Save and close the file (in `nano`: `Ctrl+X`, then `Y`, then `Enter`).

    **Security Note:** Ensure the `.env` file has restrictive permissions (`chmod 600 .env`) and is never committed to Git.

### 3. Build and Run with Docker Compose

From the project root directory (`ARPF-TI`), use Docker Compose to build the image (which now includes the database) and start the container:

```bash
docker-compose up --build -d
```

*   `up`: Creates and starts containers. It will also create the log volume (`log_data`).
*   `--build`: Forces Docker Compose to build the image based on the `Dockerfile` before starting the container. You can omit this flag if the image is already built and up-to-date.
*   `-d`: Runs the containers in detached mode (in the background).

This command reads the `docker-compose.yml` file, builds the `app` service image (including `db.sqlite3`), creates the log volume, and starts the container, automatically loading variables from `.env`.

### 4. Apply Database Migrations (If Needed)

Since the database is now part of the image, migrations should ideally be applied *before* building the image if there are model changes. However, if you need to run migrations on the existing database within the container (e.g., for initial setup if the committed DB is empty), you can use `docker-compose exec`:

```bash
docker-compose exec app python manage.py migrate
```

*   `docker-compose exec app`: Executes a command inside the running service container named `app`.
*   `python manage.py migrate`: Runs the standard Django migration command within the container.

You might also need to create a superuser:

```bash
docker-compose exec app python manage.py createsuperuser
```

**Important:** Changes made via `migrate` or `createsuperuser` inside the running container **will not persist** if you stop and remove the container (`docker-compose down`) because the database file is part of the image, not a volume. To make persistent DB changes, modify the `db.sqlite3` file locally, commit it, and rebuild the image.

### 5. Access the Application

Your ARPF-TI application should now be running. Open a web browser and navigate to:

`http://<your_ubuntu_server_ip>:8000`

Replace `<your_ubuntu_server_ip>` with the actual IP address of your Ubuntu machine.

### 6. Viewing Logs

To view the application logs being generated by the container (logs are still stored in a volume):

```bash
docker-compose logs -f app
```

Press `Ctrl+C` to stop following the logs.

### 7. Stopping the Application

To stop the running application:

```bash
docker-compose down
```

This command stops and removes the containers. Use `docker-compose stop` if you only want to stop the containers without removing them.

### 8. Restarting the Application

If you stopped the application with `docker-compose stop`, you can restart it with:

```bash
docker-compose start
```

If you stopped it with `docker-compose down`, simply run `docker-compose up -d` again (it will use the existing image unless you add `--build`).

### 9. Updating the Application

1.  Pull the latest code changes: `git pull origin main` (or your branch).
2.  **Important:** If there were database changes (migrations applied locally, data added/modified in `db.sqlite3`), ensure the updated `db.sqlite3` file is committed.
3.  Rebuild the image and restart the container with Docker Compose:
    ```bash
    docker-compose up --build -d
    ```

## Next Steps (Recommended)

*   **Nginx Reverse Proxy:** Set up Nginx as a reverse proxy. You can run Nginx in another Docker container managed by the same `docker-compose.yml` file.
*   **Database Strategy:** Reconsider using a dedicated database service (like PostgreSQL or MySQL) running in a separate container with a volume for production environments, as managing the SQLite file in Git/Docker images can be cumbersome and lead to issues.