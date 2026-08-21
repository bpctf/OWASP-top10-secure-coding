import os
import jwt
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

# Our FastAPI app name.
app = FastAPI()

# Never put the secret key in production.
SECRET_ENCODE_KEY = os.getenv("SECRET_KEY")

# The encode algorithm to use. We use HS256 over RS256 because this is just a single simple program.
# If different independent services need to decode a payload then you use RS256.
ALG = "HS256"

# This tells FastAPI that we need a bearer token and it will exchange credentials for a token in the defined endpoint.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Fake database example.
# Never put plain-text passwords in your database. This is purely for the sake of this exercise.
DB = {
    1: {"id": 1, "username": "alice", "role": "user", "pass": "123"},
    2: {"id": 2, "username": "bob", "role": "admin", "pass": "admin123"}
}

@app.post("/login")
def login(login_data: OAuth2PasswordRequestForm = Depends()):
    """ Login endpoint that depends on the FastAPI OAuth2PasswordRequestForm.

        Args:
            login_data (OAuth2PasswordRequestForm): The login data used in the login form by the user (username and password).

        Returns:
            dict: A dictionary of the encoded access token and the token_type.
    """
    # Get all the info from the database.
    info = next( (info for info in DB.values() if info["username"] == login_data.username and info["pass"] == login_data.password), None)
    
    # If we don't find info throw an exception.
    if not info:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Wrong username or password")
    
    # All the info we need from the database. The user id, the role, and an expiration timer of 10 minutes.
    payload = {
        "id": str(info["id"]),
        "username": info["username"],
        "role": info["role"],
        "expiration": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    }

    # Encode the payload above with our secret key and algorithm.
    token = jwt.encode(payload, SECRET_ENCODE_KEY, algorithm=ALG)

    # Return the encoded payload.
    return {"access_token": token, "token_type": "bearer"}

def get_user(token: str = Depends(oauth2_scheme)):
    """ Decode our JWT token and get the user information from it.

        Args:
            token (str): The token which comes from our oauth2_scheme which gets the token from the login endpoint.

        Returns:
            dict: A dict of the user id and their role.
    """
    try:
        # Try to decode the payload and get the information we care about from it.
        decoded_payload = jwt.decode(token, SECRET_ENCODE_KEY, algorithms=[ALG])
        user_id = int(decoded_payload.get("id"))
        role = decoded_payload.get("role")
        
        # If the user_id extracted is None raise an exception.
        if user_id is None:
            raise HTTPException(status_code = 401, detail="Invalid auth credentials")
        
        # Return the user id and role.
        return {"id": user_id, "role": role}

    # Raise an expired signature exception if the timer from our payload has gone over.
    # This is automatically handled by JWT.
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Token has expired. Please login again",
            headers = {"WWW-Authenticate": "Bearer"}
        )
    
    # Raise an invalid token exception is something else goes wrong.
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Could not validate credentials",
            headers = {"WWW-Authenticate": "Bearer"},
        )

@app.get("/api/user-profile")
def get_user_profile(
    user_id: int, 
    current_user: dict = Depends(get_user)
):
    """ The user-profile endpoint that will give user information after successful login.

        Args:
            user_id (int): An integer which tells us the id of the user.
            current_user (dict): The dict returned by the get_user function which this endpoint depends on.

        Return:
            dict: Returns a dict which lets us know the query was successful and data to present to the user (their id and username).
    """
    # If the current_user is not the current user and not an admin error out.
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail = "Unauthorized access"
        )
        
    # Get the user data from the database based on the user_id.
    user_data = DB.get(user_id)
        
    # If there is nothing returned error out.
    if not user_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
    # Extract only data we want to pass to the user - nothing sensitive.
    safe_user_data = { "id": user_data["id"], "username": user_data["username"] }
        
    # Return a dict that will tell the user the query was successful and the curated user data from above.
    return {
        "status": "success",
        "data": safe_user_data
    }

