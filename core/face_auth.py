import os
import cv2
import numpy as np
import logging
import json
import base64
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, Optional, List

class FaceAuthManager:
    def __init__(self, storage_path: str = "face_data"):
        """
        Initialize Face Authentication Manager
        
        Args:
            storage_path: Directory to store face encodings
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        self._setup_logging()
        
        # Load the face detection model
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        
    def _setup_logging(self):
        """Configure logging for face authentication operations"""
        logging.basicConfig(
            filename='face_auth.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def register_face(self, user_id: str, image_data: bytes, username: str = None) -> Tuple[bool, str]:
        """
        Register a user's face
        
        Args:
            user_id: User identifier
            image_data: Image bytes data
            username: Optional username to associate with the face data
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Convert image bytes to numpy array
            image_array = np.frombuffer(image_data, np.uint8)
            image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
            
            # Convert to grayscale for face detection
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Check image quality to ensure good registration quality
            blur_value = cv2.Laplacian(gray, cv2.CV_64F).var()
            if blur_value < 50:  # Same threshold as in verification
                logging.warning(f"Low quality image detected during registration, blur value: {blur_value}")
                return False, "Image quality too low. Please ensure: \n1. You are in a well-lit area\n2. Your face is clearly visible\n3. The camera lens is clean\n4. You're not moving while taking the photo"
            
            # Log the blur value for debugging purposes
            logging.info(f"Image quality check passed during registration, blur value: {blur_value}")
            
            # Provide guidance if image quality is marginal but acceptable
            if blur_value < 80:
                logging.info(f"Marginal image quality during registration, blur value: {blur_value}")
                # Continue with registration but note the marginal quality
            
            # Use more lenient face detection parameters
            faces = self.face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.2,
                minNeighbors=4,
                minSize=(30, 30)
            )
            
            if len(faces) == 0:
                return False, "No face detected in the image"
            
            # If multiple faces are detected, use the largest one for registration
            if len(faces) > 1:
                logging.info(f"Multiple faces detected during registration for user {user_id}, using largest face")
                # Find the face with the largest area (width * height)
                largest_face_idx = 0
                largest_face_area = 0
                
                for i, (x, y, w, h) in enumerate(faces):
                    area = w * h
                    if area > largest_face_area:
                        largest_face_area = area
                        largest_face_idx = i
                
                # Use the largest face
                x, y, w, h = faces[largest_face_idx]
            else:
                # Extract the only face detected
                x, y, w, h = faces[0]
            
            face_image = image[y:y+h, x:x+w]
            
            # Resize face to standard size for consistency
            face_image = cv2.resize(face_image, (150, 150))
            
            # Convert to grayscale for feature extraction
            face_gray = cv2.cvtColor(face_image, cv2.COLOR_BGR2GRAY)
            
            # Extract simple features (using Histogram of Oriented Gradients would be better, 
            # but we'll use a simple approach for compatibility)
            face_encoding = self._extract_features(face_gray)
            
            # Save the face encoding and face image
            face_data = {
                "encoding": face_encoding.tolist(),
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
            
            # Store username if provided
            if username:
                face_data["username"] = username
            
            # Save to file
            user_face_file = self.storage_path / f"{user_id}.json"
            with open(user_face_file, "w") as f:
                json.dump(face_data, f)
                
            # Also save the face image for reference
            face_img_path = self.storage_path / f"{user_id}_face.jpg"
            cv2.imwrite(str(face_img_path), face_image)
                
            logging.info(f"Face data registered for user {user_id}")
            
            return True, "Face registered successfully"
            
        except Exception as e:
            logging.error(f"Error in face registration: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            return False, f"Face registration failed: {str(e)}"
    
    def verify_face(self, user_id: str, image_data: bytes, tolerance: float = 0.35, username: str = None) -> Tuple[bool, str]:
        """
        Verify a user's face against stored face data with enhanced security
        
        Args:
            user_id: User identifier
            image_data: Image bytes data
            tolerance: Match tolerance (lower is stricter)
            username: Optional username for additional verification
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Enhanced security: Log verification attempt with timestamp
            logging.info(f"Face verification attempt for user_id: {user_id} at {datetime.now().isoformat()}")
            
            # Check if user has registered face data
            user_face_file = self.storage_path / f"{user_id}.json"
            if not user_face_file.exists():
                logging.warning(f"Verification attempt for unregistered face: {user_id}")
                return False, "User has not registered face data"
            
            # Load stored face encoding
            with open(user_face_file, "r") as f:
                face_data = json.load(f)
            
            # Enhanced security: Check if username matches the stored data if provided
            if username and 'username' in face_data and face_data['username'] != username:
                logging.warning(f"Username mismatch during verification. Expected: {face_data.get('username')}, Got: {username}")
                return False, "Identity verification failed. Username mismatch."
                
            stored_encoding = np.array(face_data["encoding"])
            
            # Process the verification image
            image_array = np.frombuffer(image_data, np.uint8)
            image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
            
            # Convert to grayscale for face detection
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Enhanced security: Apply image quality check with more lenient threshold
            blur_value = cv2.Laplacian(gray, cv2.CV_64F).var()
            # Lower threshold from 100 to 50 for better user experience
            if blur_value < 50:  # More lenient threshold for blurry images
                logging.warning(f"Low quality image detected during verification for user {user_id}, blur value: {blur_value}")
                return False, "Image quality too low. Please use a clearer image in good lighting conditions."
            
            # Log the blur value for debugging purposes
            logging.info(f"Image quality check passed for user {user_id}, blur value: {blur_value}")
            
            # Use more lenient face detection parameters
            faces = self.face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.2,  # Increased from 1.1 to reduce false positives
                minNeighbors=4,   # Reduced from 5 to be more lenient
                minSize=(30, 30)
            )
            
            if len(faces) == 0:
                logging.warning(f"No face detected during verification for user {user_id}")
                return False, "No face detected in the verification image"
            
            # If multiple faces are detected, use the largest one instead of failing
            if len(faces) > 1:
                logging.info(f"Multiple faces detected during verification for user {user_id}, using largest face")
                # Find the face with the largest area (width * height)
                largest_face_idx = 0
                largest_face_area = 0
                
                for i, (x, y, w, h) in enumerate(faces):
                    area = w * h
                    if area > largest_face_area:
                        largest_face_area = area
                        largest_face_idx = i
                
                # Use the largest face
                x, y, w, h = faces[largest_face_idx]
            else:
                # Extract the only face detected
                x, y, w, h = faces[0]
            
            face_image = image[y:y+h, x:x+w]
            
            # Resize face to standard size for consistency
            face_image = cv2.resize(face_image, (150, 150))
            
            # Convert to grayscale for feature extraction
            face_gray = cv2.cvtColor(face_image, cv2.COLOR_BGR2GRAY)
            
            # Extract features
            face_encoding = self._extract_features(face_gray)
            
            # Compare face encodings
            similarity = self._calculate_similarity(stored_encoding, face_encoding)
            
            # Log the similarity score for debugging
            logging.info(f"Face verification similarity score: {similarity} for user {user_id}")
            
            # Enhanced security: Use a stricter threshold for verification
            # Higher threshold value = stricter matching requirements
            threshold = 1 - tolerance
            logging.info(f"Face verification threshold: {threshold}, actual similarity: {similarity} for user {user_id}")
            
            # Enhanced security: Track failed attempts
            if similarity <= threshold:
                # Record failed attempt
                failed_attempts = face_data.get("failed_attempts", 0) + 1
                face_data["failed_attempts"] = failed_attempts
                face_data["last_failed"] = datetime.now().isoformat()
                
                with open(user_face_file, "w") as f:
                    json.dump(face_data, f)
                
                # Log the failure with detailed information
                logging.warning(f"Face verification failed for user {user_id}, similarity: {similarity}, failed attempts: {failed_attempts}")
                return False, "Face verification failed. The face does not match our records."
            
            # Verification successful
            # Update last verified timestamp and reset failed attempts
            face_data["last_verified"] = datetime.now().isoformat()
            face_data["failed_attempts"] = 0
            
            # Enhanced security: Store username if provided and not already stored
            if username and 'username' not in face_data:
                face_data['username'] = username
                
            with open(user_face_file, "w") as f:
                json.dump(face_data, f)
                
            logging.info(f"Face verification successful for user {user_id}, similarity: {similarity}")
            return True, "Face verification successful"
                
        except Exception as e:
            logging.error(f"Error in face verification: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            return False, f"Face verification failed: {str(e)}"
    
    def _extract_features(self, face_gray: np.ndarray) -> np.ndarray:
        """
        Extract features from a grayscale face image
        
        Args:
            face_gray: Grayscale face image
            
        Returns:
            Feature vector
        """
        # Use a more robust feature extraction method
        # First, normalize the image for better feature extraction
        face_gray = cv2.equalizeHist(face_gray)
        # Use Local Binary Patterns Histogram for feature extraction
        # This is simpler than HOG used by face_recognition but works for basic faces
        lbp = self._local_binary_pattern(face_gray)
        
        # Calculate histogram to get feature vector
        hist, _ = np.histogram(lbp.ravel(), bins=256, range=(0, 256))
        
        # Normalize the histogram
        hist = hist.astype("float")
        hist /= (hist.sum() + 1e-7)
        
        return hist
        
    def _local_binary_pattern(self, image: np.ndarray) -> np.ndarray:
        """
        Simple implementation of Local Binary Pattern
        
        Args:
            image: Grayscale image
            
        Returns:
            LBP image
        """
        rows, cols = image.shape
        lbp = np.zeros_like(image)
        
        # Simple 3x3 LBP
        for i in range(1, rows-1):
            for j in range(1, cols-1):
                center = image[i, j]
                code = 0
                
                code |= (image[i-1, j-1] >= center) << 7
                code |= (image[i-1, j] >= center) << 6
                code |= (image[i-1, j+1] >= center) << 5
                code |= (image[i, j+1] >= center) << 4
                code |= (image[i+1, j+1] >= center) << 3
                code |= (image[i+1, j] >= center) << 2
                code |= (image[i+1, j-1] >= center) << 1
                code |= (image[i, j-1] >= center) << 0
                
                lbp[i, j] = code
                
        return lbp
        
    def _calculate_similarity(self, hist1: np.ndarray, hist2: np.ndarray) -> float:
        """
        Calculate similarity between two histograms
        
        Args:
            hist1: First histogram
            hist2: Second histogram
            
        Returns:
            Similarity score (0 to 1, higher is more similar)
        """
        # Calculate cosine similarity
        dot = np.dot(hist1, hist2)
        norm1 = np.linalg.norm(hist1)
        norm2 = np.linalg.norm(hist2)
        
        # Avoid division by zero
        if norm1 == 0 or norm2 == 0:
            return 0.0
            
        # Calculate cosine similarity
        cosine_similarity = dot / (norm1 * norm2)
        
        # Calculate Euclidean distance (normalized)
        euclidean_dist = np.linalg.norm(hist1 - hist2)
        max_dist = np.sqrt(len(hist1))  # Maximum possible distance
        euclidean_similarity = 1 - (euclidean_dist / max_dist)
        
        # Combine both metrics for more robust similarity (weighted average)
        # Give more weight to cosine similarity as it's more reliable for face recognition
        similarity = 0.7 * cosine_similarity + 0.3 * euclidean_similarity
        
        logging.info(f"Similarity metrics - Cosine: {cosine_similarity:.4f}, Euclidean: {euclidean_similarity:.4f}, Combined: {similarity:.4f}")
        return similarity
    
    def delete_face_data(self, user_id: str) -> bool:
        """Delete stored face data for a user"""
        try:
            user_face_file = self.storage_path / f"{user_id}.json"
            face_img_path = self.storage_path / f"{user_id}_face.jpg"
            
            files_deleted = 0
            
            if user_face_file.exists():
                os.remove(user_face_file)
                files_deleted += 1
                
            if face_img_path.exists():
                os.remove(face_img_path)
                files_deleted += 1
                
            logging.info(f"Face data deleted for user {user_id}")
            return files_deleted > 0
            
        except Exception as e:
            logging.error(f"Error deleting face data: {str(e)}")
            return False
    
    def capture_face_from_webcam(self) -> Tuple[bool, str, Optional[bytes]]:
        """
        Capture a face image from webcam
        
        Returns:
            Tuple of (success, message, image_data)
        """
        try:
            # Open webcam
            cap = cv2.VideoCapture(0)
            
            if not cap.isOpened():
                return False, "Could not access webcam", None
            
            # Wait for camera to initialize
            for _ in range(10):
                success, frame = cap.read()
                if not success:
                    continue
            
            # Capture frame
            success, frame = cap.read()
            
            # Release webcam
            cap.release()
            
            if not success:
                return False, "Failed to capture image from webcam", None
            
            # Detect face in the frame
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            
            faces = self.face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.1,
                minNeighbors=5,
                minSize=(30, 30)
            )
            
            if len(faces) == 0:
                return False, "No face detected. Please try again", None
            
            if len(faces) > 1:
                return False, "Multiple faces detected. Please ensure only one face is visible", None
            
            # Draw rectangle around the face
            for (x, y, w, h) in faces:
                cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
            
            # Convert to bytes
            success, buffer = cv2.imencode('.jpg', frame)
            if not success:
                return False, "Failed to encode image", None
            
            image_data = buffer.tobytes()
            
            return True, "Face captured successfully", image_data
            
        except Exception as e:
            logging.error(f"Error capturing face from webcam: {str(e)}")
            return False, f"Error capturing face: {str(e)}", None
            
    def get_user_face_status(self, user_id: str) -> Dict:
        """
        Get the status of a user's face authentication
        
        Args:
            user_id: User identifier
            
        Returns:
            Dictionary with face authentication status
        """
        # Check if user has face data registered
        user_face_file = self.storage_path / f"{user_id}.json"
        
        if not user_face_file.exists():
            return {
                "registered": False,
                "created_at": None,
                "last_verified": "Never verified"
            }
            
        try:
            with open(user_face_file, "r") as f:
                face_data = json.load(f)
                
            return {
                "registered": True,
                "created_at": datetime.fromisoformat(face_data.get("created_at", "2023-01-01T00:00:00")).strftime("%Y-%m-%d %H:%M"),
                "last_verified": datetime.fromisoformat(face_data.get("last_verified", "2023-01-01T00:00:00")).strftime("%Y-%m-%d %H:%M") if "last_verified" in face_data else "Never verified"
            }
        except Exception as e:
            logging.error(f"Error getting face status for user {user_id}: {str(e)}")
            return {
                "registered": False,
                "created_at": None,
                "last_verified": "Never verified",
                "error": str(e)
            }
            
    def has_face_auth(self, user_id: str) -> bool:
        """
        Check if a user has face authentication set up
        
        Args:
            user_id: User identifier
            
        Returns:
            Boolean indicating if user has face auth set up
        """
        user_face_file = self.storage_path / f"{user_id}.json"
        return user_face_file.exists()