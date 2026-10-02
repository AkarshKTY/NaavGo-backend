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


# ══════════════════════════════════════════
#  HELPER FUNCTIONS
# ══════════════════════════════════════════

def hash_password(password: str) -> str:
    """
    🔐 PASSWORD HASHING - Plain text password को secure करना
    
    Kya होता है:
    1. Random salt generate करो
    2. Password + salt को bcrypt से hash करो
    3. Hashed password return करो
    
    Example:
    Plain: "password123"
    Hashed: "$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36P4/T1e"
    
    ⚠️ IMPORTANT: हमेशा plain text password को database में store मत करो!
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """
    🔐 PASSWORD VERIFICATION - User की password check करना
    
    Kya होता है:
    1. User ने जो password enter किया वह लो
    2. Database में stored hashed password के साथ compare करो
    3. अगर match करे तो True, वर्ना False
    
    Login के समय यह function call होता है:
    user_doc = db.users.find_one({"email": email})
    if verify_password(entered_password, user_doc["password"]):
        # Login successful!
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str, role: str) -> str:
    """
    🎫 JWT TOKEN GENERATION - User के लिए token बनाना
    
    Kya होता है:
    1. Payload बनाओ: user_id, email, role, expiration
    2. JWT_SECRET से sign करो
    3. Token return करो
    
    Token को frontend AsyncStorage में store करा जाता है
    हर request में यह token Authorization header में भेजा जाता है:
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    
    ⚠️ 7 days के बाद यह token expire हो जाता है!
    """
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRATION_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(request: Request) -> Optional[dict]:
    """
    👤 GET CURRENT USER - Protected routes के लिए user verify करना
    
    Kya होता है:
    1. Authorization header से token निकालो
    2. या cookies से session_token निकालो
    3. JWT decode करके user_id निकालो
    4. Database से user का document fetch करो
    5. User return करो
    
    यह हर protected endpoint पर call होता है:
    @api_router.get("/auth/me")
    async def get_me(request: Request):
        user = await get_current_user(request)  # यह call
        if not user:
            raise HTTPException(401, "Not authenticated")
        return user
    
    Token expire हो सकता है, session token भी valid हो सकता है
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
    """
    📝 SIGNUP ENDPOINT - नया user register करना
    
    Frontend से request आता है:
    {
      name: "Raj Kumar",
      email: "raj@example.com", 
      password: "password123",
      phone: "+91 9876543210",
      role: "user"  // या "boatman"
    }
    
    Kya होता है:
    1. Check करो यह email पहले से exist करता है या नहीं
    2. Password को bcrypt से hash करो (सुरक्षा के लिए)
    3. नया user document बनाओ
    4. MongoDB users collection में insert करो
    5. JWT token generate करो (7 days expiry)
    6. Response में user data + token भेज
    
    Database में save होता है:
    {
      _id: ObjectId,
      user_id: "user_abc123",
      name: "Raj Kumar",
      email: "raj@example.com",
      password: "$2b$12$...",  // Hashed password (never plain text!)
      phone: "+91 9876543210",
      role: "user",
      picture: null,
      created_at: timestamp
    }
    """
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
    """
    🔐 LOGIN ENDPOINT - Existing user को login करना
    
    Frontend से request:
    { email: "raj@example.com", password: "password123" }
    
    Kya होता है:
    1. MongoDB में email से user खोजो
    2. Password को bcrypt से verify करो
    3. अगर match करे तो JWT token generate करो
    4. Token + user data response में भेज
    
    Frontend यह token लेगा:
    - AsyncStorage में save करेगा
    - हर request के साथ Authorization header में भेजेगा
    """
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

@api_router.post("/auth/google/session")
async def exchange_google_session(data: SessionDataRequest, response: Response):
    """
    🌐 GOOGLE OAUTH ENDPOINT - Google से login करना
    
    Emergent Auth Service से Google OAuth handle होती है
    Frontend से request: { session_id: "abc123xyz" }
    
    Kya होता है:
    1. Emergent API को call करो session_id के साथ
    2. Emergent से user का email, name, picture मिलता है
    3. Check करो यह user पहले से exist करता है
    4. अगर नहीं है तो नया user create करो
    5. Session token को database में store करो
    6. httpOnly cookie set करो
    
    ⚠️ IMPORTANT: URLs hardcoded हैं - production में environment variables से लो!
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


# ══════════════════════════════════════════
#  BOATS ROUTES
# ══════════════════════════════════════════

@api_router.get("/boats", response_model=List[BoatResponse])
async def get_boats(ghat: Optional[str] = None):
    """
    🚤 GET ALL BOATS ENDPOINT - Home screen में सभी boats list करना
    
    Frontend से request: GET /api/boats?ghat=Dashashwamedh
    
    Kya होता है:
    1. Optional ghat parameter check करो
    2. अगर ghat है तो filter करो
    3. MongoDB boats collection से सभी boats fetch करो
    4. Response में array of boats भेज
    
    Response:
    [
      {
        boat_id: "boat_xyz",
        name: "Ram Ji Ki Naav",
        price: 100,
        rating: 4.5,
        seats: 4,
        ghat: "Dashashwamedh",
        boatman_name: "Ramesh Nishad",
        status: "available",
        ...
      }
    ]
    """
    query = {}
    if ghat and ghat != "All Ghats":
        query["ghat"] = ghat
    
    boats = await db.boats.find(query, {"_id": 0}).to_list(100)
    return boats

@api_router.get("/boats/{boat_id}", response_model=BoatResponse)
async def get_boat(boat_id: str):
    """
    🚤 GET SINGLE BOAT ENDPOINT - Detail screen के लिए ek boat की full info
    
    Frontend से request: GET /api/boats/boat_xyz
    
    Kya होता है:
    1. boat_id से boat खोजो
    2. सभी details के साथ return करो (reviews, images, etc)
    3. अगर नहीं मिला तो 404 error
    """
    boat = await db.boats.find_one({"boat_id": boat_id}, {"_id": 0})
    if not boat:
        raise HTTPException(status_code=404, detail="Boat not found")
    return boat

@api_router.patch("/boats/{boat_id}/status")
async def update_boat_status(boat_id: str, status: str, request: Request):
    """
    🚤 UPDATE BOAT STATUS ENDPOINT - Boatman अपने boat को busy/available set करता है
    
    Frontend से request: PATCH /api/boats/boat_xyz/status
    Body: { status: "busy" }
    
    Kya होता है:
    1. Boatman को verify करो (token से)
    2. Boat को find करो
    3. Status update करो (available/busy)
    4. Updated_at timestamp update करो
    
    Use case:
    - Boatman busy हो तो status = "busy" करो
    - Ride complete हो तो status = "available" करो
    """
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
    """
    📅 CREATE BOOKING ENDPOINT - नया booking create करना
    
    Frontend से request:
    {
      boat_id: "boat_xyz",
      passengers: 2,
      ride_type: "shared",        // shared या private
      date: "2024-04-27",
      time: "5:30 AM"
    }
    
    Kya होता है:
    1. User को verify करो (token से)
    2. Boat को verify करो कि exist करता है और available है
    3. Total price calculate करो (passengers * boat_price)
    4. Booking ID generate करो
    5. MongoDB bookings collection में insert करो
    6. Booking response में QR code के लिए booking_code भेज
    
    Database में save होता है:
    {
      _id: ObjectId,
      booking_id: "booking_abc",
      booking_code: "NV-1234",
      user_id: "user_xyz",
      boat_id: "boat_xyz",
      passengers: 2,
      ride_type: "shared",
      date: "2024-04-27",
      time: "5:30 AM",
      total_price: 300,
      status: "confirmed",
      created_at: timestamp
    }
    """
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
    booking_code = f"NV-{random.randint(1000, 9999)}"  # QR code के लिए
    
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
                "emoji": "🛶",
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
                "status": "busy",
                "emoji": "🚤",
                "sky_colors": ["#c7d2fe", "##818cf8"],
                "water_colors": ["#4f46e5", "#312e81"],
                "busy_time": "20 min"
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
            "status": "available",  # Auto-approved for demo
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
