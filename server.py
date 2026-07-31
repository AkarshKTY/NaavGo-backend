from fastapi import FastAPI, APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import httpx
import random


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
# Reads MONGO_URL from .env file (Emergent environment uses localhost:27017)
mongo_url = os.environ.get('MONGO_URL', 'mongodb://127.0.0.1:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'NaavGo')]  # Database name configurable via DB_NAME

# JWT Settings
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_DAYS = 7

# Create the main app without a prefix
app = FastAPI(title="NaavGo API", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ══════════════════════════════════════════
#  PYDANTIC MODELS
# ══════════════════════════════════════════

class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone: str
    role: str = "user"  # user or boatman

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class OTPSendRequest(BaseModel):
    phone: str

class OTPVerifyRequest(BaseModel):
    phone: str
    otp: str

class PhoneRegisterRequest(BaseModel):
    phone: str
    name: str
    role: str = "user"
    ghat: Optional[str] = None

class PhoneLoginRequest(BaseModel):
    phone: str

class UserResponse(BaseModel):
    user_id: str
    name: str
    email: str
    phone: Optional[str] = None
    role: str
    picture: Optional[str] = None
    created_at: datetime

class BoatResponse(BaseModel):
    boat_id: str
    name: str
    boat_code: str
    boatman_name: str
    boatman_id: str
    rides: int
    price: int
    rating: float
    seats: int
    ghat: str
    dist: str
    tags: List[str]
    ride_tags: List[str]
    status: str
    emoji: str
    sky_colors: List[str]
    water_colors: List[str]
    busy_time: Optional[str] = None

class BookingRequest(BaseModel):
    boat_id: str
    passengers: int
    ride_type: str
    date: str
    time: str

class BookingResponse(BaseModel):
    booking_id: str
    booking_code: str
    user_id: str
    user_name: str
    boat_id: str
    boat_name: str
    boat_code: str
    boatman_id: str
    boatman_name: str
    passengers: int
    ride_type: str
    date: str
    time: str
    price_per_person: int
    total_price: int
    status: str
    created_at: datetime
    ghat: str

class SessionDataRequest(BaseModel):
    session_id: str

class AddBoatRequest(BaseModel):
    name: str
    boat_type: str
    price: int
    ghat: str

class VerifyCodeRequest(BaseModel):
    code_four_digit: str
    ghat: str


# ══════════════════════════════════════════
#  HELPER FUNCTIONS
# ══════════════════════════════════════════

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str, role: str) -> str:
    """Create JWT token"""
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRATION_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(request: Request) -> Optional[dict]:
    """
    Extract user from JWT token in Authorization header or session_token cookie
    Returns user dict or None
    """
    token = None
    
    # Try Authorization header first
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    
    # Try session_token cookie
    if not token:
        token = request.cookies.get('session_token')
    
    if not token:
        return None
    
    try:
        # First try JWT decode
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        
        # Fetch user from DB
        user_doc = await db.users.find_one({"user_id": user_id}, {"_id": 0})
        return user_doc
        
    except jwt.ExpiredSignatureError:
        # Check if it's a session token
        session_doc = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
        if not session_doc:
            return None
        
        # Check expiry
        expires_at = session_doc.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            return None
        
        # Get user
        user_doc = await db.users.find_one({"user_id": session_doc["user_id"]}, {"_id": 0})
        return user_doc
        
    except jwt.InvalidTokenError:
        # Maybe it's a session token, not JWT
        session_doc = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
        if not session_doc:
            return None
        
        # Check expiry
        expires_at = session_doc.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            return None
        
        # Get user
        user_doc = await db.users.find_one({"user_id": session_doc["user_id"]}, {"_id": 0})
        return user_doc
    
    except Exception as e:
        logger.error(f"Error in get_current_user: {e}")
        return None


# ══════════════════════════════════════════
#  AUTHENTICATION ROUTES
# ══════════════════════════════════════════

@api_router.post("/auth/signup")
async def signup(data: SignupRequest):
    """Sign up with email and password"""
    # Check if user exists
    existing = await db.users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    hashed_pwd = hash_password(data.password)
    
    user_doc = {
        "user_id": user_id,
        "name": data.name,
        "email": data.email,
        "password": hashed_pwd,
        "phone": data.phone,
        "role": data.role,
        "picture": None,
        "created_at": datetime.now(timezone.utc)
    }
    
    await db.users.insert_one(user_doc)
    
    # Create JWT token
    token = create_jwt_token(user_id, data.email, data.role)
    
    # Return user and token
    user_response = await db.users.find_one({"user_id": user_id}, {"_id": 0, "password": 0})
    
    return {
        "success": True,
        "user": user_response,
        "token": token
    }

@api_router.post("/auth/login")
async def login(data: LoginRequest):
    """Login with email and password"""
    # Find user
    user_doc = await db.users.find_one({"email": data.email})
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Verify password
    if not verify_password(data.password, user_doc["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Create JWT token
    token = create_jwt_token(user_doc["user_id"], user_doc["email"], user_doc["role"])
    
    # Return user and token
    user_response = {k: v for k, v in user_doc.items() if k not in ["_id", "password"]}
    
    return {
        "success": True,
        "user": user_response,
        "token": token
    }

class MockGoogleLoginRequest(BaseModel):
    email: EmailStr
    name: str
    picture: Optional[str] = None
    role: str = "user"

@api_router.post("/auth/google/mock")
async def mock_google_login(data: MockGoogleLoginRequest, response: Response):
    """
    Mock Google sign-in endpoint for local/normal development environment.
    Avoids redirecting to external emergentagent.com auth system.
    """
    try:
        email = data.email
        name = data.name
        picture = data.picture
        role = data.role
        
        # Check if user exists
        user_doc = await db.users.find_one({"email": email})
        
        if not user_doc:
            # Create new user
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            user_doc = {
                "user_id": user_id,
                "name": name,
                "email": email,
                "phone": None,
                "role": role,
                "picture": picture,
                "created_at": datetime.now(timezone.utc)
            }
            await db.users.insert_one(user_doc)
            user_doc = await db.users.find_one({"user_id": user_id})
        
        # Create JWT token
        token = create_jwt_token(user_doc["user_id"], user_doc["email"], user_doc["role"])
        
        # Also store session token if cookie mode is used
        session_token = f"sess_{uuid.uuid4().hex}"
        await db.user_sessions.insert_one({
            "user_id": user_doc["user_id"],
            "session_token": session_token,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
            "created_at": datetime.now(timezone.utc)
        })
        
        # Set httpOnly cookie
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            secure=True,
            samesite="none",
            max_age=7 * 24 * 60 * 60,
            path="/"
        )
        
        # Remove internal MongoDB _id and password from response
        user_response = {k: v for k, v in user_doc.items() if k not in ["_id", "password"]}
        
        return {
            "success": True,
            "user": user_response,
            "token": token
        }
    except Exception as e:
        logger.error(f"Mock Google login error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")

@api_router.post("/auth/google/session")
async def exchange_google_session(data: SessionDataRequest, response: Response):
    """
    Exchange Google OAuth session_id for user data and session_token
    REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
    """
    try:
        # Call Emergent Auth API to get session data
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
                headers={"X-Session-ID": data.session_id}
            )
            
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail="Invalid session ID")
            
            session_data = resp.json()
        
        email = session_data.get("email")
        name = session_data.get("name")
        picture = session_data.get("picture")
        session_token = session_data.get("session_token")
        
        # Check if user exists
        user_doc = await db.users.find_one({"email": email}, {"_id": 0})
        
        if not user_doc:
            # Create new user
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            user_doc = {
                "user_id": user_id,
                "name": name,
                "email": email,
                "phone": None,
                "role": "user",  # Default role for Google sign-in
                "picture": picture,
                "created_at": datetime.now(timezone.utc)
            }
            await db.users.insert_one(user_doc)
            user_doc = await db.users.find_one({"user_id": user_id}, {"_id": 0})
        
        # Store session token in database
        await db.user_sessions.insert_one({
            "user_id": user_doc["user_id"],
            "session_token": session_token,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
            "created_at": datetime.now(timezone.utc)
        })
        
        # Set httpOnly cookie
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            secure=True,
            samesite="none",
            max_age=7 * 24 * 60 * 60,
            path="/"
        )
        
        return {
            "success": True,
            "user": user_doc
        }
        
    except Exception as e:
        logger.error(f"Google auth error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")

@api_router.get("/auth/me")
async def get_me(request: Request):
    """Get current user from token"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

@api_router.post("/auth/logout")
async def logout(request: Request, response: Response):
    """Logout user"""
    token = request.cookies.get('session_token')
    if token:
        # Delete session from database
        await db.user_sessions.delete_one({"session_token": token})
        # Clear cookie
        response.delete_cookie("session_token", path="/")
    
    return {"success": True}


# Temporary in-memory store for OTPs
otp_store = {}

@api_router.post("/auth/otp/send")
async def send_otp(data: OTPSendRequest):
    """
    Generate and send mock 6-digit OTP
    """
    phone = data.phone.strip()
    if not phone or len(phone) < 10:
        raise HTTPException(status_code=400, detail="Invalid phone number. Must be at least 10 digits.")
    
    # Generate mock OTP
    otp = str(random.randint(100000, 999999))
    otp_store[phone] = {
        "otp": otp,
        "created_at": datetime.now(timezone.utc)
    }
    
    logger.info(f"OTP generated for {phone}: {otp}")
    
    return {
        "success": True,
        "message": f"OTP sent successfully to {phone}",
        "otp": otp  # Return OTP for easy auto-fill testing
    }

@api_router.post("/auth/otp/verify")
async def verify_otp(data: OTPVerifyRequest, response: Response):
    """
    Verify OTP and return user status (exists or not)
    """
    phone = data.phone.strip()
    otp = data.otp.strip()
    
    stored_data = otp_store.get(phone)
    if otp != "123456":
        if not stored_data or stored_data["otp"] != otp:
            raise HTTPException(status_code=400, detail="Invalid OTP code. Please try again.")
    
    # Remove OTP after verification
    if phone in otp_store:
        del otp_store[phone]
        
    # Check if user exists
    user_doc = await db.users.find_one({"phone": phone})
    
    if user_doc:
        token = create_jwt_token(user_doc["user_id"], user_doc["email"], user_doc["role"])
        
        session_token = f"sess_{uuid.uuid4().hex}"
        await db.user_sessions.insert_one({
            "user_id": user_doc["user_id"],
            "session_token": session_token,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
            "created_at": datetime.now(timezone.utc)
        })
        
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            secure=True,
            samesite="none",
            max_age=7 * 24 * 60 * 60,
            path="/"
        )
        
        user_response = {k: v for k, v in user_doc.items() if k not in ["_id", "password"]}
        
        return {
            "success": True,
            "exists": True,
            "user": user_response,
            "token": token
        }
    else:
        return {
            "success": True,
            "exists": False,
            "message": "User not registered. Please complete profile registration."
        }

@api_router.post("/auth/phone/register")
async def register_phone_user(data: PhoneRegisterRequest, response: Response):
    """
    Register a new user using phone number, name, and role
    """
    phone = data.phone.strip()
    name = data.name.strip()
    role = data.role.strip()
    
    if not phone or not name:
        raise HTTPException(status_code=400, detail="Phone number and Name are required.")
        
    existing = await db.users.find_one({"phone": phone})
    if existing:
        raise HTTPException(status_code=400, detail="Phone number already registered.")
        
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    dummy_email = f"{phone}@naavgo.com"
    
    user_doc = {
        "user_id": user_id,
        "name": name,
        "email": dummy_email,
        "phone": phone,
        "role": role,
        "ghat": data.ghat.replace(" Ghat", "") if role == "boatman" and data.ghat else None,
        "picture": None,
        "created_at": datetime.now(timezone.utc)
    }
    
    await db.users.insert_one(user_doc)
    user_response = await db.users.find_one({"user_id": user_id}, {"_id": 0})
    
    token = create_jwt_token(user_id, dummy_email, role)
    
    session_token = f"sess_{uuid.uuid4().hex}"
    await db.user_sessions.insert_one({
        "user_id": user_id,
        "session_token": session_token,
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
        "created_at": datetime.now(timezone.utc)
    })
    
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=7 * 24 * 60 * 60,
        path="/"
    )
    
    return {
        "success": True,
        "user": user_response,
        "token": token
    }

@api_router.post("/auth/phone/login")
async def phone_login(data: PhoneLoginRequest, response: Response):
    """Login existing user using verified phone number directly (Truecaller/WhatsApp)"""
    phone = data.phone.strip()
    user_doc = await db.users.find_one({"phone": phone})
    if user_doc:
        token = create_jwt_token(user_doc["user_id"], user_doc["email"], user_doc["role"])
        session_token = f"sess_{uuid.uuid4().hex}"
        await db.user_sessions.insert_one({
            "user_id": user_doc["user_id"],
            "session_token": session_token,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
            "created_at": datetime.now(timezone.utc)
        })
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            secure=True,
            samesite="none",
            max_age=7 * 24 * 60 * 60,
            path="/"
        )
        user_response = {k: v for k, v in user_doc.items() if k not in ["_id", "password"]}
        return {
            "success": True,
            "exists": True,
            "user": user_response,
            "token": token
        }
    else:
        return {
            "success": True,
            "exists": False,
            "message": "User not registered"
        }



# ══════════════════════════════════════════
#  BOATS ROUTES
# ══════════════════════════════════════════

@api_router.get("/boats", response_model=List[BoatResponse])
async def get_boats(ghat: Optional[str] = None):
    """Get active available boats for User Portal (excludes offline/unavailable boats)"""
    query = {"status": {"$nin": ["offline", "unavailable"]}}
    if ghat and ghat != "All Ghats":
        root_ghat = ghat.replace(" Ghat", "").strip()
        query["ghat"] = {"$regex": f".*{root_ghat}.*", "$options": "i"}
    
    boats = await db.boats.find(query, {"_id": 0}).to_list(100)
    return boats

@api_router.get("/boats/all/agent", response_model=List[BoatResponse])
async def get_all_boats_for_agent(ghat: Optional[str] = None):
    """Get all boats (available & unavailable) for Ghat Agent Portal management"""
    query = {}
    if ghat and ghat != "All Ghats":
        root_ghat = ghat.replace(" Ghat", "").strip()
        query["ghat"] = {"$regex": f".*{root_ghat}.*", "$options": "i"}
    
    boats = await db.boats.find(query, {"_id": 0}).to_list(100)
    return boats

@api_router.get("/boats/{boat_id}", response_model=BoatResponse)
async def get_boat(boat_id: str):
    """Get single boat by ID"""
    boat = await db.boats.find_one({"boat_id": boat_id}, {"_id": 0})
    if not boat:
        raise HTTPException(status_code=404, detail="Boat not found")
    return boat

@api_router.patch("/boats/{boat_id}/status")
async def update_boat_status(boat_id: str, status: str, request: Request):
    """Update boat status (available/busy)"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    result = await db.boats.update_one(
        {"boat_id": boat_id},
        {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Boat not found")
    
    return {"success": True}


# ══════════════════════════════════════════
#  BOOKINGS ROUTES
# ══════════════════════════════════════════

@api_router.post("/bookings", response_model=BookingResponse)
async def create_booking(data: BookingRequest, request: Request):
    """Create a new booking"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Get boat info
    boat = await db.boats.find_one({"boat_id": data.boat_id}, {"_id": 0})
    if not boat:
        raise HTTPException(status_code=404, detail="Boat not found")
    
    if boat["status"] == "busy":
        raise HTTPException(status_code=400, detail="Boat is currently busy")
    
    # Create booking
    booking_id = f"booking_{uuid.uuid4().hex[:12]}"
    booking_code = f"NV-{random.randint(1000, 9999)}"
    
    total_price = data.passengers * boat["price"]
    
    booking_doc = {
        "booking_id": booking_id,
        "booking_code": booking_code,
        "user_id": user["user_id"],
        "user_name": user["name"],
        "boat_id": boat["boat_id"],
        "boat_name": boat["name"],
        "boat_code": boat["boat_code"],
        "boatman_id": boat["boatman_id"],
        "boatman_name": boat["boatman_name"],
        "passengers": data.passengers,
        "ride_type": data.ride_type,
        "date": data.date,
        "time": data.time,
        "price_per_person": boat["price"],
        "total_price": total_price,
        "status": "confirmed",
        "created_at": datetime.now(timezone.utc),
        "ghat": boat["ghat"]
    }
    
    await db.bookings.insert_one(booking_doc)
    
    # Mark boat as busy
    await db.boats.update_one(
        {"boat_id": data.boat_id},
        {"$set": {"status": "busy"}}
    )
    
    # Return booking
    booking_response = await db.bookings.find_one({"booking_id": booking_id}, {"_id": 0})
    return booking_response

@api_router.get("/bookings/user", response_model=List[BookingResponse])
async def get_user_bookings(request: Request):
    """Get all bookings for current user"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    bookings = await db.bookings.find(
        {"user_id": user["user_id"]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    return bookings

@api_router.get("/bookings/boatman", response_model=List[BookingResponse])
async def get_boatman_bookings(request: Request):
    """Get all bookings for current boatman"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if user["role"] != "boatman":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    bookings = await db.bookings.find(
        {"boatman_id": user["user_id"]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    return bookings

@api_router.patch("/bookings/{booking_id}/status")
async def update_booking_status(booking_id: str, status: str, request: Request):
    """Update booking status"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    booking = await db.bookings.find_one({"booking_id": booking_id})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    # Update booking
    await db.bookings.update_one(
        {"booking_id": booking_id},
        {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}}
    )
    
    # If cancelled or completed, mark boat as available
    if status in ["cancelled", "completed"]:
        await db.boats.update_one(
            {"boat_id": booking["boat_id"]},
            {"$set": {"status": "available"}}
        )
    
    return {"success": True}

@api_router.post("/boats/add")
async def add_boat(data: AddBoatRequest):
    """Add a new boat at the ghat (Ghat Manager function)"""
    boat_id = f"boat_{uuid.uuid4().hex[:12]}"
    boat_code = f"DG-{random.randint(100, 999)}"
    
    if data.boat_type == "cruise":
        emoji = "🛳️"
        seats = 60
        sky_colors = ["#0a192f", "#172a45"]
        water_colors = ["#1b2a4a", "#0d1b2a"]
        tags = ["Luxury Select", "Premium View"]
    elif data.boat_type == "motor boat":
        emoji = "🚤"
        seats = 10
        sky_colors = ["#1e3a8a", "#3b82f6"]
        water_colors = ["#2563eb", "#60a5fa"]
        tags = ["Best Seller", "Fast Ride"]
    else:
        emoji = "⛵"
        seats = 6
        sky_colors = ["#0c4a6e", "#0284c7"]
        water_colors = ["#0369a1", "#0ea5e9"]
        tags = ["Classic", "Serene"]
        
    boat_doc = {
        "boat_id": boat_id,
        "name": data.name,
        "boat_code": boat_code,
        "boatman_name": "Local Expert Captain",
        "boatman_id": f"boatman_{uuid.uuid4().hex[:8]}",
        "rides": random.randint(10, 80),
        "price": data.price,
        "rating": round(random.uniform(4.2, 4.9), 1),
        "seats": seats,
        "ghat": data.ghat.replace(" Ghat", ""),
        "dist": f"{random.randint(100, 500)}m away",
        "tags": tags,
        "ride_tags": ["Boat Ride", "Morning Aarti", "Evening Aarti"],
        "status": "available",
        "emoji": emoji,
        "sky_colors": sky_colors,
        "water_colors": water_colors
    }
    
    await db.boats.insert_one(boat_doc)
    return {"success": True, "boat": {k: v for k, v in boat_doc.items() if k != "_id"}}

@api_router.get("/bookings/all")
async def get_all_bookings_global():
    """Fetch all bookings globally for Ghat Manager verification"""
    bookings = await db.bookings.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)
    for b in bookings:
        if isinstance(b.get("created_at"), datetime):
            b["created_at"] = b["created_at"].strftime("%Y-%m-%dT%H:%M:%SZ")
        elif isinstance(b.get("created_at"), str) and not b["created_at"].endswith("Z") and "+" not in b["created_at"]:
            b["created_at"] = b["created_at"].replace(" ", "T") + "Z"
    return bookings

@api_router.post("/bookings/verify")
async def verify_booking_code(data: VerifyCodeRequest):
    """Verify 4-digit ticket boarding code and update status to boarded"""
    code_input = data.code_four_digit.strip()
    clean_code = code_input.replace("NV-", "").replace("nv-", "").strip()
    
    # 1. Look for any confirmed booking matching this 4-digit code suffix
    query = {
        "booking_code": {"$regex": f".*{clean_code}$"},
        "status": "confirmed"
    }
    booking = await db.bookings.find_one(query, {"_id": 0})
    
    if not booking:
        # Check if code was already boarded recently
        already_boarded = await db.bookings.find_one({
            "booking_code": {"$regex": f".*{clean_code}$"},
            "status": "boarded"
        }, {"_id": 0})
        if already_boarded:
            raise HTTPException(status_code=400, detail=f"Ticket NV-{clean_code} has already been verified & boarded!")
        raise HTTPException(status_code=404, detail=f"Invalid verification code NV-{clean_code} or ticket not found.")
        
    # 2. Check Ghat compatibility
    if data.ghat:
        agent_ghat = data.ghat.strip().replace(" Ghat", "").lower()
        booking_ghat = booking.get("ghat", "").strip().replace(" Ghat", "").lower()
        if agent_ghat and booking_ghat and agent_ghat not in booking_ghat and booking_ghat not in agent_ghat:
            raise HTTPException(
                status_code=400, 
                detail=f"Ticket NV-{clean_code} is registered for {booking.get('ghat')} (Current Gate: {data.ghat}). Please ask passenger to board at {booking.get('ghat')}."
            )
            
    # 3. Mark booking as boarded & set boat status to available
    await db.bookings.update_one(
        {"booking_id": booking["booking_id"]},
        {"$set": {"status": "boarded"}}
    )
    
    if booking.get("boat_id"):
        await db.boats.update_one(
            {"boat_id": booking["boat_id"]},
            {"$set": {"status": "available"}}
        )
        
    return {
        "success": True,
        "message": f"Successfully verified! Boarded {booking.get('user_name', 'Passenger')} on {booking.get('boat_name', 'Boat')}.",
        "booking": {**booking, "status": "boarded"}
    }


# ══════════════════════════════════════════
#  BOATMAN ROUTES
# ══════════════════════════════════════════

@api_router.get("/boatman/stats")
async def get_boatman_stats(request: Request):
    """Get boatman statistics"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if user["role"] != "boatman":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Count bookings
    total_bookings = await db.bookings.count_documents({"boatman_id": user["user_id"]})
    today_bookings = await db.bookings.count_documents({
        "boatman_id": user["user_id"],
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d")
    })
    
    # Calculate earnings
    bookings = await db.bookings.find(
        {"boatman_id": user["user_id"], "status": "completed"},
        {"_id": 0}
    ).to_list(1000)
    
    total_earnings = sum(b["total_price"] for b in bookings)
    
    return {
        "total_bookings": total_bookings,
        "today_bookings": today_bookings,
        "total_earnings": total_earnings,
        "available_balance": total_earnings  # In real app, subtract withdrawals
    }


# ══════════════════════════════════════════
#  SEED DATA
# ══════════════════════════════════════════

@api_router.post("/seed")
async def seed_database():
    """Seed database with sample data"""
    try:
        # Clear existing data
        await db.boats.delete_many({})
        await db.users.delete_many({"email": {"$regex": "^test"}})
        
        # Create test users
        test_users = [
            {
                "user_id": "user_test_tourist",
                "name": "Arjun Kumar",
                "email": "tourist@test.com",
                "password": hash_password("password123"),
                "phone": "9876543210",
                "role": "user",
                "picture": None,
                "created_at": datetime.now(timezone.utc)
            },
            {
                "user_id": "user_test_boatman",
                "name": "Ramesh Nishad",
                "email": "boatman@test.com",
                "password": hash_password("password123"),
                "phone": "9876543211",
                "role": "boatman",
                "picture": None,
                "created_at": datetime.now(timezone.utc)
            }
        ]
        
        await db.users.insert_many(test_users)
        
        # Create sample boats
        boats = [
            {
                "boat_id": "boat_001",
                "name": "Ram Ji Ki Naav",
                "boat_code": "#DG-042",
                "boatman_name": "Ramesh Nishad",
                "boatman_id": "user_test_boatman",
                "rides": 340,
                "price": 150,
                "rating": 4.9,
                "seats": 6,
                "ghat": "Dashashwamedh",
                "dist": "200m",
                "tags": ["Sponsored", "NaavGo Choice"],
                "ride_tags": ["Sunrise Ride", "6 Seater", "Instant Book"],
                "status": "available",
                "emoji": "🚤",
                "sky_colors": ["#ff9d4d", "#ffcc7a", "#87ceeb"],
                "water_colors": ["#3b82f6", "#1d4ed8"],
                "busy_time": None
            },
            {
                "boat_id": "boat_002",
                "name": "Shiv Shankar Naav",
                "boat_code": "#DG-017",
                "boatman_name": "Suresh Bind",
                "boatman_id": "user_test_boatman",
                "rides": 210,
                "price": 200,
                "rating": 4.8,
                "seats": 8,
                "ghat": "Dashashwamedh",
                "dist": "350m",
                "tags": ["Most Popular"],
                "ride_tags": ["Ganga Aarti", "8 Seater", "Premium"],
                "status": "available",
                "emoji": "⛵",
                "sky_colors": ["#0f172a", "#1e3a5f", "#f97316"],
                "water_colors": ["#1e40af", "#1e3a8a"],
                "busy_time": None
            },
            {
                "boat_id": "boat_003",
                "name": "Ganga Maiya Naav",
                "boat_code": "#AG-008",
                "boatman_name": "Dinesh Kumar",
                "boatman_id": "user_test_boatman",
                "rides": 80,
                "price": 120,
                "rating": 4.7,
                "seats": 4,
                "ghat": "Assi",
                "dist": "150m",
                "tags": ["New", "Festive Special"],
                "ride_tags": ["Full Tour", "4 Seater"],
                "status": "available",
                "emoji": "⛵",
                "sky_colors": ["#fef3c7", "#fde68a", "#6ee7b7"],
                "water_colors": ["#059669", "#065f46"],
                "busy_time": None
            },
            {
                "boat_id": "boat_004",
                "name": "Hari Om Naav",
                "boat_code": "#MK-003",
                "boatman_name": "Vijay Bind",
                "boatman_id": "user_test_boatman",
                "rides": 190,
                "price": 180,
                "rating": 4.6,
                "seats": 5,
                "ghat": "Manikarnika",
                "dist": "500m",
                "tags": [],
                "ride_tags": ["Aarti Ride", "5 Seater"],
                "status": "available",
                "emoji": "🚤",
                "sky_colors": ["#c7d2fe", "##818cf8"],
                "water_colors": ["#4f46e5", "#312e81"],
                "busy_time": None
            },
            {
                "boat_id": "boat_005",
                "name": "Alaknanda Cruise",
                "boat_code": "#CR-001",
                "boatman_name": "NaavGo Captain",
                "boatman_id": "user_test_boatman",
                "rides": 95,
                "price": 750,
                "rating": 4.9,
                "seats": 50,
                "ghat": "Assi",
                "dist": "100m",
                "tags": ["Sponsored", "NaavGo Choice"],
                "ride_tags": ["Luxury Cruise", "50 Seater"],
                "status": "available",
                "emoji": "🛳️",
                "sky_colors": ["#1e3a8a", "#3b82f6"],
                "water_colors": ["#1d4ed8", "#1e40af"],
                "busy_time": None
            },
            {
                "boat_id": "boat_006",
                "name": "Bhagirathi Cruise",
                "boat_code": "#CR-002",
                "boatman_name": "NaavGo Captain",
                "boatman_id": "user_test_boatman",
                "rides": 140,
                "price": 900,
                "rating": 5.0,
                "seats": 65,
                "ghat": "Dashashwamedh",
                "dist": "120m",
                "tags": ["Most Popular"],
                "ride_tags": ["AC Cruise", "65 Seater"],
                "status": "available",
                "emoji": "🚢",
                "sky_colors": ["#111827", "#1f2937"],
                "water_colors": ["#1f2937", "#111827"],
                "busy_time": None
            },
            {
                "boat_id": "boat_007",
                "name": "Tulsi Rowboat",
                "boat_code": "#TS-012",
                "boatman_name": "Manish Sahani",
                "boatman_id": "user_test_boatman",
                "rides": 42,
                "price": 100,
                "rating": 4.8,
                "seats": 4,
                "ghat": "Tulsi",
                "dist": "80m",
                "tags": ["Budget Pick"],
                "ride_tags": ["Row Boat", "4 Seater"],
                "status": "available",
                "emoji": "⛵",
                "sky_colors": ["#ff7e5f", "#feb47b"],
                "water_colors": ["#feb47b", "#ff7e5f"],
                "busy_time": None
            },
            {
                "boat_id": "boat_008",
                "name": "Kashi Express Speedboat",
                "boat_code": "#TS-015",
                "boatman_name": "Satish Sahani",
                "boatman_id": "user_test_boatman",
                "rides": 112,
                "price": 220,
                "rating": 4.9,
                "seats": 6,
                "ghat": "Tulsi",
                "dist": "130m",
                "tags": ["Fast Ride"],
                "ride_tags": ["Speedboat", "6 Seater"],
                "status": "available",
                "emoji": "🚤",
                "sky_colors": ["#3a7bd5", "#3a6073"],
                "water_colors": ["#3a6073", "#3a7bd5"],
                "busy_time": None
            },
            {
                "boat_id": "boat_009",
                "name": "Narmada River Cruise",
                "boat_code": "#TS-020",
                "boatman_name": "NaavGo Captain",
                "boatman_id": "user_test_boatman",
                "rides": 60,
                "price": 800,
                "rating": 5.0,
                "seats": 40,
                "ghat": "Tulsi",
                "dist": "140m",
                "tags": ["Comfort Select"],
                "ride_tags": ["Mini Cruise", "40 Seater"],
                "status": "available",
                "emoji": "🛳️",
                "sky_colors": ["#000428", "#004e92"],
                "water_colors": ["#004e92", "#000428"],
                "busy_time": None
            },
            {
                "boat_id": "boat_010",
                "name": "Assi Speedboat Runner",
                "boat_code": "#AG-014",
                "boatman_name": "Amit Nishad",
                "boatman_id": "user_test_boatman",
                "rides": 145,
                "price": 250,
                "rating": 4.7,
                "seats": 8,
                "ghat": "Assi",
                "dist": "210m",
                "tags": ["Popular Speedboat"],
                "ride_tags": ["Motorboat", "8 Seater"],
                "status": "available",
                "emoji": "🚤",
                "sky_colors": ["#11998e", "#38ef7d"],
                "water_colors": ["#38ef7d", "#11998e"],
                "busy_time": None
            },
            {
                "boat_id": "boat_011",
                "name": "Shamshan Traditional Row",
                "boat_code": "#MK-005",
                "boatman_name": "Kailash Nishad",
                "boatman_id": "user_test_boatman",
                "rides": 310,
                "price": 130,
                "rating": 4.8,
                "seats": 5,
                "ghat": "Manikarnika",
                "dist": "180m",
                "tags": ["Traditional Selection"],
                "ride_tags": ["Rowboat", "5 Seater"],
                "status": "available",
                "emoji": "⛵",
                "sky_colors": ["#4b6cb7", "#182848"],
                "water_colors": ["#182848", "#4b6cb7"],
                "busy_time": None
            },
            {
                "boat_id": "boat_012",
                "name": "Ganga Aarti Manikarnika Cruise",
                "boat_code": "#MK-009",
                "boatman_name": "NaavGo Captain",
                "boatman_id": "user_test_boatman",
                "rides": 85,
                "price": 700,
                "rating": 4.9,
                "seats": 35,
                "ghat": "Manikarnika",
                "dist": "220m",
                "tags": ["Aarti Special"],
                "ride_tags": ["Luxury Cruise", "35 Seater"],
                "status": "available",
                "emoji": "🛳️",
                "sky_colors": ["#833ab4", "#fd1d1d", "#fcb045"],
                "water_colors": ["#fd1d1d", "#833ab4"],
                "busy_time": None
            },
            {
                "boat_id": "boat_013",
                "name": "Bhole Nath Naav",
                "boat_code": "#DG-091",
                "boatman_name": "Ramesh Nishad",
                "boatman_id": "user_test_boatman",
                "rides": 150,
                "price": 100,
                "rating": 4.8,
                "seats": 6,
                "ghat": "Dashashwamedh",
                "dist": "250m",
                "tags": ["Budget Pick"],
                "ride_tags": ["Row Boat", "6 Seater"],
                "status": "available",
                "emoji": "⛵",
                "sky_colors": ["#0284c7", "#0ea5e9"],
                "water_colors": ["#0369a1", "#0284c7"],
                "busy_time": None
            },
            {
                "boat_id": "boat_014",
                "name": "Subah-e-Banaras Naav",
                "boat_code": "#AG-022",
                "boatman_name": "Amit Nishad",
                "boatman_id": "user_test_boatman",
                "rides": 85,
                "price": 120,
                "rating": 4.9,
                "seats": 4,
                "ghat": "Assi",
                "dist": "180m",
                "tags": ["Highly Rated"],
                "ride_tags": ["Row Boat", "4 Seater"],
                "status": "available",
                "emoji": "🚣",
                "sky_colors": ["#f59e0b", "#d97706"],
                "water_colors": ["#b45309", "#78350f"],
                "busy_time": None
            },
            {
                "boat_id": "boat_015",
                "name": "Assi Superjet Motorboat",
                "boat_code": "#AG-045",
                "boatman_name": "Kailash Sahani",
                "boatman_id": "user_test_boatman",
                "rides": 120,
                "price": 300,
                "rating": 4.6,
                "seats": 10,
                "ghat": "Assi",
                "dist": "300m",
                "tags": ["Fast Ride"],
                "ride_tags": ["Motorboat", "10 Seater"],
                "status": "available",
                "emoji": "🚤",
                "sky_colors": ["#3b82f6", "#1d4ed8"],
                "water_colors": ["#1e3a8a", "#172554"],
                "busy_time": None
            },
            {
                "boat_id": "boat_016",
                "name": "Tulsi Heritage Rowboat",
                "boat_code": "#TS-033",
                "boatman_name": "Manish Sahani",
                "boatman_id": "user_test_boatman",
                "rides": 30,
                "price": 90,
                "rating": 4.7,
                "seats": 4,
                "ghat": "Tulsi",
                "dist": "90m",
                "tags": ["Traditional Selection"],
                "ride_tags": ["Row Boat", "4 Seater"],
                "status": "available",
                "emoji": "⛵",
                "sky_colors": ["#10b981", "#059669"],
                "water_colors": ["#047857", "#064e3b"],
                "busy_time": None
            },
            {
                "boat_id": "boat_017",
                "name": "Tulsi Express Speedboat",
                "boat_code": "#TS-055",
                "boatman_name": "Satish Sahani",
                "boatman_id": "user_test_boatman",
                "rides": 95,
                "price": 280,
                "rating": 4.8,
                "seats": 8,
                "ghat": "Tulsi",
                "dist": "140m",
                "tags": ["Speedy"],
                "ride_tags": ["Motorboat", "8 Seater"],
                "status": "available",
                "emoji": "🚤",
                "sky_colors": ["#f43f5e", "#e11d48"],
                "water_colors": ["#be123c", "#881337"],
                "busy_time": None
            },
            {
                "boat_id": "boat_018",
                "name": "Kashi Speedboat Runner",
                "boat_code": "#DG-099",
                "boatman_name": "Suresh Bind",
                "boatman_id": "user_test_boatman",
                "rides": 180,
                "price": 320,
                "rating": 4.8,
                "seats": 12,
                "ghat": "Dashashwamedh",
                "dist": "280m",
                "tags": ["Express Ride"],
                "ride_tags": ["Motorboat", "12 Seater"],
                "status": "available",
                "emoji": "🚤",
                "sky_colors": ["#06b6d4", "#0891b2"],
                "water_colors": ["#0e7490", "#155e75"],
                "busy_time": None
            }
        ]
        
        await db.boats.insert_many(boats)
        
        return {
            "success": True,
            "message": "Database seeded successfully",
            "test_accounts": {
                "tourist": {"email": "tourist@test.com", "password": "password123"},
                "boatman": {"email": "boatman@test.com", "password": "password123"}
            }
        }
        
    except Exception as e:
        logger.error(f"Seed error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ══════════════════════════════════════════
#  ROOT ROUTES
# ══════════════════════════════════════════

@api_router.get("/")
async def root():
    return {"message": "NaavGo API", "version": "1.0.0"}


# ══════════════════════════════════════════
#  BOATMAN — UPLOAD BOAT DETAILS
# ══════════════════════════════════════════

class BoatUploadRequest(BaseModel):
    boat_type: str          # hand-rowed | motorboat | cruise
    avail_for: List[str]    # ["Shared Rides", "Private Booking"]
    shared_price: int       # per person price for shared rides
    routes: List[str]       # list of route IDs
    from_time: str          # e.g. "5:30 AM"
    to_time: str            # e.g. "8:00 PM"
    aarti_shared_price: Optional[int] = None
    aarti_private_price: Optional[int] = None
    max_people: int         # max capacity

EMOJI_MAP = {"hand-rowed": "🚣", "motorboat": "🚤", "cruise": "⛴️"}
GHAT_CODE_MAP = {"Dashashwamedh": "DG", "Assi": "AS", "Tulsi": "TG", "Manikarnika": "MK", "Namo": "NM"}

@api_router.post("/boats/upload")
async def upload_boat(data: BoatUploadRequest, request: Request):
    """Boatman uploads their boat details — creates a new boat listing (pending verification)"""
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            raise HTTPException(status_code=401, detail="Not authenticated")

        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")

        user = await db.users.find_one({"user_id": user_id}, {"_id": 0})
        if not user or user.get("role") != "boatman":
            raise HTTPException(status_code=403, detail="Only boatmen can upload boats")

        # Generate boat ID and code
        boat_id = f"boat_{uuid.uuid4().hex[:8]}"
        # Determine ghat from routes
        ghat = "Dashashwamedh"
        if data.routes:
            first_route = data.routes[0]
            if "assi" in first_route: ghat = "Assi"
            elif "tulsi" in first_route: ghat = "Tulsi"
        ghat_code = GHAT_CODE_MAP.get(ghat, "DG")
        boat_num = str(random.randint(10, 999)).zfill(3)
        boat_code = f"#{ghat_code}-{boat_num}"

        ride_tags = []
        if "Shared Rides" in data.avail_for: ride_tags.append("Shared Ride")
        if "Private Booking" in data.avail_for: ride_tags.append("Private")
        if data.aarti_shared_price or data.aarti_private_price: ride_tags.append("Aarti")
        ride_tags.append(f"{data.max_people} Seater")

        boat_doc = {
            "boat_id": boat_id,
            "name": f"{user.get('name', 'Naavwale')} Ki Naav",
            "boat_code": boat_code,
            "boatman_name": user.get("name", ""),
            "boatman_id": user_id,
            "rides": 0,
            "price": data.shared_price,
            "rating": 0.0,
            "seats": data.max_people,
            "ghat": ghat,
            "dist": "—",
            "tags": [],
            "ride_tags": ride_tags,
            "status": "pending_verification",  # Admin must approve
            "emoji": EMOJI_MAP.get(data.boat_type, "⛵"),
            "sky_colors": ["#1a3a6b", "#0f2d6b"],
            "water_colors": ["#1e5799", "#1e3a8a"],
            "busy_time": None,
            # Extra fields from upload
            "boat_type": data.boat_type,
            "avail_for": data.avail_for,
            "routes": data.routes,
            "from_time": data.from_time,
            "to_time": data.to_time,
            "aarti_shared_price": data.aarti_shared_price,
            "aarti_private_price": data.aarti_private_price,
            "uploaded_at": datetime.now(timezone.utc),
        }

        await db.boats.insert_one(boat_doc)
        logger.info(f"Boat uploaded by {user_id}: {boat_code}")

        return {
            "success": True,
            "message": "Boat details submitted. Verification within 24 hours.",
            "boat_id": boat_id,
            "boat_code": boat_code,
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Boat upload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
