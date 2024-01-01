# DETI STORE

#### Project 2 - SIO

---

## Index

1. Introduction

2. Overview

3. Vulnerabilites

## 1. Introduction

This project was developed for the "Informatics Security and Organizations" course as part of the Bachelor's degree in Informatics Engineering at the University of Aveiro.

## 2. Overview

The application is a simple online store that allows users to browse and purchase products. The application is divided into two main components: the client and the server. The client is a web application that allows users to browse and purchase products. The server is a Flask application that provides the client with the necessary data to display the products and allows users to purchase products.

The main objective of this project is to identify and mitigate vulnerabilities in the application. The vulnerabilities are divided into various categories following the ASVS standard. The vulnerabilities are described in the following sections.

## 3. Vulnerabilites Solved

### 3.1 Communications Security Requirements (V9.1.1)

"Verify that secured TLS is used for all client connectivity, and does not fall back to insecure or unencrypted protocols." ([C8](https://owasp.org/www-project-proactive-controls/#div-numbering))

Nowadays, it's almost mandatory to have a secure connection between the client and the server. This is done by using HTTPS to encrypt the data transmitted between the client and the server. This ensures that the data is not intercepted by third parties and that the data is not modified during transmission.

HTTPS is a protocol that uses TLS/SSL to encrypt the data transmitted between the client and the server. TLS/SSL uses asymmetric cryptography to establish a secure connection between the client and the server. This is done by using a public key and a private key. The public key is used to encrypt the data and the private key is used to decrypt the data. This ensures that only the server can decrypt the data transmitted by the client and vice versa.

Our application uses HTTPS to communicate with the client. This is done by using a load balancer that redirects all HTTP requests to HTTPS. This is done by using the following nginx configuration:

```nginx
upstream web {
    server web:5000;
}

server {
    listen 80;
    server_name localhost;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate cert.pem;
    ssl_certificate_key key.pem;

    location / {
      proxy_pass https://web;
      proxy_set_header Host "localhost";
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

In our Flask application we redirect all HTTP requests to HTTPS we use the following code:

```python
@app.before_request
    def before_request():
        if (
            not request.is_secure
            and request.headers.get("X-Forwarded-Proto") != "https"
        ):
            url = request.url.replace("http://", "https://", 1)
            code = 301
            return redirect(url, code=code)
```

With this code, we ensure that all requests made to our Flask application are transmitted securely via HTTPS, enhancing the overall security of the communication channel and protecting sensitive user data.

**Note:**

While a self-signed certificate suffices for testing purposes, it is crucial to obtain a valid SSL/TLS certificate from a trusted certificate authority for production environments. This not only ensures the security of user data but also establishes trust among users by displaying the padlock symbol in the browser's address bar.

![](./images/PrivacyError.png)

As we can see in the image above, the browser warns the user that the connection is not secure. This is because the certificate is self-signed and not issued by a trusted certificate authority. This is not a problem for testing purposes, but it is a problem for production environments.

![](./images/https.png)

After clicking on "Advanced" and proceeding to the website, we can see that we are connected via HTTPS. With this type of connection, the data is encrypted and transmitted securely.

![](./images/certificate.png)

We can also see that the certificate is self-signed and not issued by a trusted certificate authority. A certificate containes information about the issuer, the validity period, the domain name, etc. In this case, the certificate is issued by the domain name "localhost" and is valid for 365 days.

To obtain this certificate we used the following command:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj "/C=PT/ST=Aveiro/L=Aveiro/O=UA/OU=UA/CN=localhost"
```

openssl is a command-line tool that can be used to generate certificates. In this case, we used the req command to generate a self-signed certificate. The -x509 option specifies that we want to generate a self-signed certificate. The -newkey option specifies that we want to generate a new key. The rsa:4096 option specifies that we want to generate a 4096-bit RSA key. The -nodes option specifies that we do not want to encrypt the private key. The -out option specifies the output file. The -keyout option specifies the private key file. The -days option specifies the number of days the certificate is valid. The -subj option specifies the subject of the certificate. The subject contains information about the issuer, the validity period, the domain name, etc. In this case, the certificate is issued by the domain name "localhost" and is valid for 365 days.

### 3.2 File Upload Requirements (V12.1.2)

"Verify that the application will not accept large files that could fill up storage or cause a denial of service."

File upload is a common feature in web applications. However, it is also a common source of vulnerabilities. This is because the uploaded files can contain malicious code that can be executed on the server. To prevent this, it is necessary to validate the uploaded files and ensure that they do not contain malicious code.

Besides validating the uploaded files, it is also necessary to ensure that the uploaded files are not too large. This is because large files can cause a denial of service attack by consuming all the server's resources.

In our application, we allow users to upload an image when creating an account. This image is then displayed on the user's profile page. To prevent malicious code from being uploaded, we validate the uploaded file and ensure that it is an image while also ensuring that the image is not too large. This is done by using the following code:

```python
if profile_picture:
        if (
            profile_picture.filename.endswith(".png")
            or profile_picture.filename.endswith(".jpeg")
            or profile_picture.filename.endswith(".jpg")
        ):
            try:
                upload_folder = "static/images/profile_pictures"
                file_name = email + "_" + profile_picture.filename
                os.makedirs(upload_folder, exist_ok=True)

                # Save the file to the directory
                profile_picture.save(os.path.join(upload_folder, file_name))

                #  check if picture is bigger than 5MB
                if os.path.getsize(upload_folder + "/" + file_name) / (1024 * 1024) > 5:
                    # remove the file
                    os.remove(upload_folder + "/" + file_name)
                    flash("A imagem não pode ter mais de 5MB!", category="danger")
                    return redirect(url_for("register.regist"))

                # encrypt email and phone number
                email_key = E.generate_key()
                phone_key = E.generate_key()
                # store the keys
                E.store_key(email_key, f"{user.upper()}_EMAIL_KEY")
                E.store_key(phone_key, f"{user.upper()}_PHONE_KEY")
                email_enc = E.chacha20_encrypt(email, email_key)
                phone_enc = E.chacha20_encrypt(phone, phone_key)
                if email_enc is None or phone_enc is None:
                    flash("Erro ao encriptar email ou número de telefone!")
                    return redirect(url_for("register.regist"))

                new_user = User(
                    username=user,
                    password=generate_password_hash(key),
                    name=nome,
                    email=email_enc,
                    phone=phone_enc,
                    image=upload_folder + "/" + file_name,
                    security_question=security_question,
                    google_account=False,
                )
            except Exception as e:
                print(e)
                flash("Erro ao fazer upload da imagem!", category="danger")
                return redirect(url_for("register.regist"))
        else:
            flash(
                "Por favor insira uma imagem com extensão .png ou .jpeg ou .jpg",
                category="danger",
            )
            return redirect(url_for("register.regist"))
```

First we make sure that the uploaded file is an image by checking the file extension. Then we check if the image is too large. If the image is too large, we remove the image and display an error message. If the image is not too large, we encrypt the user's email and phone number and store the encryption keys. By setting a treshold of 5MB, we ensure that the image is not too large and that it does not consume too much space on the server.

In case the user tries to upload an image bigger than 5MB, the following error message is displayed:

![](./images/image_too_large.png)

## 3.3 Session Logout and Timeout Requirements (V3.3.2)

"If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period" ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)).

Session management is a crucial part of any web application. It is important to ensure that the user's session is terminated when the user logs out or when the session expires. This is done by checking if the user is logged in and if the session has expired. If the user is logged in and the session has not expired, the user will be asked to login again, thus ensuring that the user's session is terminated.

This type of protection is important because it prevents unauthorized users from accessing the user's account.

For this in added a parameter to the User table in the database called "last_activity_time" that stores the last time the user logged in. This parameter is updated every time the user logs in. This is done by using the following code:

```python
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(100), nullable=True)
    isAdmin = db.Column(db.Boolean, default=False)
    username = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(100), nullable=True)
    image = db.Column(
        db.String(20), nullable=False, default="../static/images/default.jpg"
    )
    security_question = db.Column(db.String(100), nullable=True)
    cart = db.relationship("Cart", backref="user")
    wishlist = db.relationship("Wishlist", backref="user")
    google_account = db.Column(db.Boolean, default=False)
    last_activity_time = db.Column(db.DateTime, default=datetime.utcnow) # here
    verification_code = db.Column(db.String(100), nullable=True, default=None)
    verification_timestamp = db.Column(db.Integer, default=0)
```

Then, when the user tries to access a page, we check if the user is logged in and if the session has expired. This is done by using the following code:

```python
@login_required
def recheck_login():
    # Check if re-authentication is needed based on the configured periods
    idle_period_limit = datetime.utcnow() - timedelta(days=30)  # L1: 30 days
    actively_used_limit = datetime.utcnow() - timedelta(hours=12)  # L2: 12 hours

    if current_user.last_activity_time < idle_period_limit:
        # Re-authenticate for idle period
        flash("Please re-enter your password to continue.", "danger")

        logout_user()

        return redirect(url_for("auth.login"))

    if current_user.last_activity_time < actively_used_limit:
        # Re-authenticate for actively used period
        flash("Please re-enter your password to continue.", "danger")

        logout_user()

        return redirect(url_for("auth.login"))
```

If the user is logged in and the session has not expired, the user will be asked to login again and this message in shown:

![](./images/relogin.png)

## 3.4 Error Handling (V7.4.1)

"Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique ID which support personnel can use to investigate." ([C10](https://owasp.org/www-project-proactive-controls/#div-numbering))

Error handling is an important part of any application. It is important to ensure that the user is informed of any errors that occur. This is done by displaying an error message to the user. This error message should be generic and should not contain any sensitive information. This is because the error message can be used by attackers to gain information about the application.

For this we used logging from the python library. This allows us to log any errors that occur in the application. This is done by using the following code:

```python
def handle_error(e):
    error_id = generate_unique_error_id()
    # check if datetime as atribute utcnow
    if hasattr(datetime, "utcnow"):
        timestamp = datetime.utcnow().isoformat()
    else:
        timestamp = datetime.datetime.now().isoformat()
    user_info = (
        f"User: {current_user.username}"
        if current_user.is_authenticated
        else "User: Not authenticated"
    )
    logger.error(
        "Error ID: %s\nTimestamp: %s\n%s\n%s", error_id, timestamp, user_info, str(e)
    )

    flash(
        "Ocorreu um erro inesperado. Por favor, entre em contato com o suporte com o ID do erro: "
        + error_id,
        category="danger",
    )
    return render_template("index.html")


def generate_unique_error_id():
    return str(uuid.uuid4())
```

This allows us to log any errors that occur in the application and display a generic error message to the user. An id is attributed to each error so that the support team can identify the error and fix it.

![](./images/error.jpeg)

As we can see in the image above, the error message is generic and does not contain any sensitive information. This is because the error message can be used by attackers to gain information about the application.

## 3.5 & 3.6 Log Content Requirements (V7.1.1) & (V7.1.2)

"Verify that the application does not log credentials or payment details. Session tokens should only be stored in logs in an irreversible, hashed form." ([C9, C10](https://owasp.org/www-project-proactive-controls/#div-numbering))

"Verify that the application does not log other sensitive data as defined under local privacy laws or relevant security policy." ([C9](https://owasp.org/www-project-proactive-controls/#div-numbering))

Logging is an important part of any application. It is important to ensure that the application logs all the necessary information. However, it is also important to ensure that the application does not log sensitive information. This is because the log files can be accessed by attackers and used to gain information about the application.

To prevent this, we ensure that the application does not log sensitive information by removing all the logs that contain information about the application, user's credentials, payment details, etc.

This way attackers cannot gain information about the application by accessing the log files.

## 3.7 Dependency (V14.2.1)

"Verify that all components are up to date, preferably using a dependency checker during build or compile time"

Dependencies are an important part of any application. However, it is important to ensure that the dependencies are up to date. This is because outdated dependencies can contain vulnerabilities that can be exploited by attackers.

To ensure that we resort to a dependency checker called "safety" and a dependency "pip-check".

This dependencies were added to our requirements.txt which is the used by the dockerfile to install the dependencies.

```dockerfile
FROM python:3.11
WORKDIR /app
ENV FLASK_APP=__init__.py
ENV FLASK_RUN_HOST=0.0.0.0
RUN apt update -y
RUN apt install gcc musl-dev wkhtmltopdf -y
COPY requirements.txt requirements.txt
RUN python -m venv venv
RUN venv/bin/pip install --upgrade pip && venv/bin/pip install -r requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt
RUN pip-check
RUN safety check
EXPOSE 5000
COPY . .
CMD ["bash", "-c", "\
    export FLASK_APP=__init__.py && \
    export FLASK_DEBUG=1 && \
    flask run --cert=cert.pem --key=key.pem"]
```

This dependencies ensure that all the dependencies are up to date and that there are no vulnerabilities in the dependencies.
