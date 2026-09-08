import os
import io
import numpy as np
from PIL import Image
import cv2

def analyze_face(image_bytes: bytes, filename: str):
    """Complete Face OSINT Analysis"""

    result = {
        "filename":       filename,
        "face_detected":  False,
        "face_count":     0,
        "faces":          [],
        "deepfake_check": {},
        "reverse_search": {},
        "risk_score":     0,
        "risk_level":     "LOW"
    }

    try:
        # Convert bytes to numpy
        nparr = np.frombuffer(image_bytes, np.uint8)
        img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img_cv is None:
            # Try PIL method
            try:
                img_pil = Image.open(io.BytesIO(image_bytes))
                if img_pil.mode != 'RGB':
                    img_pil = img_pil.convert('RGB')
                img_cv = cv2.cvtColor(np.array(img_pil), cv2.COLOR_RGB2BGR)
            except Exception as e:
                result["error"] = f"Image decode failed: {str(e)}"
                return result

        # Save temp
        tmp_path = "/tmp/face_analysis.jpg"
        cv2.imwrite(tmp_path, img_cv)

        # 1 — Face Detection using OpenCV (Fast!)
        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )
        eye_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_eye.xml'
        )

        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=3,
            minSize=(20,20)
        )

        if len(faces) > 0:
            result["face_detected"] = True
            result["face_count"]    = len(faces)

            face_list = []
            for i, (x,y,w,h) in enumerate(faces):
                # Get face region
                face_roi = gray[y:y+h, x:x+w]

                # Eye detection in face
                eyes = eye_cascade.detectMultiScale(face_roi)
                has_eyes = len(eyes) > 0

                face_info = {
                    "face_number": i + 1,
                    "location": {
                        "x": int(x), "y": int(y),
                        "w": int(w), "h": int(h)
                    },
                    "has_eyes":    has_eyes,
                    "face_size":   f"{int(w)}x{int(h)} pixels",
                    "confidence":  "High" if w > 100 else "Medium",
                }

                # Try DeepFace with timeout
                try:
                    import signal

                    def timeout_handler(signum, frame):
                        raise TimeoutError("DeepFace timeout")

                    signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(15)  # 15 second timeout

                    from deepface import DeepFace
                    analysis = DeepFace.analyze(
                        img_path=tmp_path,
                        actions=["age","gender","emotion","race"],
                        enforce_detection=False,
                        detector_backend='opencv',
                        silent=True
                    )

                    signal.alarm(0)  # Cancel timeout

                    if not isinstance(analysis, list):
                        analysis = [analysis]

                    if i < len(analysis):
                        a = analysis[i]
                        face_info["age"]     = a.get("age","Unknown")
                        face_info["gender"]  = a.get("dominant_gender","Unknown")
                        face_info["emotion"] = a.get("dominant_emotion","Unknown")
                        face_info["race"]    = a.get("dominant_race","Unknown")
                        face_info["emotion_scores"] = {
                            k: round(float(v),2)
                            for k,v in a.get("emotion",{}).items()
                        }
                        face_info["gender_scores"] = {
                            k: round(float(v),2)
                            for k,v in a.get("gender",{}).items()
                        }

                except TimeoutError:
                    face_info["note"] = "DeepFace analysis timed out — basic detection done"
                    face_info["age"]     = "Unknown"
                    face_info["gender"]  = "Unknown"
                    face_info["emotion"] = "Unknown"
                    face_info["race"]    = "Unknown"
                except Exception as e:
                    face_info["note"] = f"Basic detection only: {str(e)[:50]}"
                    face_info["age"]     = "Unknown"
                    face_info["gender"]  = "Unknown"
                    face_info["emotion"] = "Unknown"

                face_list.append(face_info)

            result["faces"] = face_list

        else:
            result["face_detected"] = False
            result["note"] = "No face detected — try with clear frontal face photo"

        # 2 — Deepfake Detection (Fast - no AI)
        try:
            indicators = []
            score = 0

            h, w = img_cv.shape[:2]

            # Square check
            if abs(w-h) < 10 and w in [256,512,1024,2048]:
                indicators.append("Square dimensions — common in AI generated images")
                score += 20

            # Sharpness/smoothness
            gray_img = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
            laplacian = cv2.Laplacian(gray_img, cv2.CV_64F)
            variance = float(laplacian.var())

            if variance < 50:
                indicators.append(f"Very smooth ({variance:.1f}) — possible AI generation")
                score += 30
            elif variance < 100:
                indicators.append(f"Slightly smooth ({variance:.1f})")
                score += 10

            # Color analysis
            b,g,r = cv2.split(img_cv)
            b_std = float(np.std(b))
            g_std = float(np.std(g))
            r_std = float(np.std(r))

            if abs(b_std-g_std)<2 and abs(g_std-r_std)<2:
                indicators.append("Unusual color uniformity — AI pattern")
                score += 15

            # Metadata check
            try:
                img_pil = Image.open(tmp_path)
                try:
                    exif = img_pil._getexif()
                    if exif:
                        from PIL.ExifTags import TAGS
                        exif_data = {TAGS.get(k,k):str(v) for k,v in exif.items()}
                        software = exif_data.get("Software","").lower()
                        ai_tools = ["midjourney","stable diffusion","dall-e",
                                   "firefly","runway","artbreeder"]
                        for tool in ai_tools:
                            if tool in software:
                                indicators.append(f"AI software detected: {tool}")
                                score += 60
                                break
                        if not exif_data.get("Make"):
                            indicators.append("No camera manufacturer data")
                            score += 10
                    else:
                        indicators.append("No camera EXIF data found")
                        score += 10
                except:
                    indicators.append("Could not read EXIF metadata")
            except:
                pass

            score = min(100, score)
            result["deepfake_check"] = {
                "score":      score,
                "suspected":  score >= 30,
                "indicators": indicators,
                "verdict":    "⚠ POSSIBLE AI/DEEPFAKE IMAGE" if score>=30 else "✅ LIKELY REAL IMAGE",
                "confidence": f"{score}% fake probability",
                "sharpness":  round(variance, 2)
            }

        except Exception as e:
            result["deepfake_check"] = {
                "error":   str(e),
                "verdict": "Analysis failed",
                "score":   0
            }

        # 3 — Reverse Search Links
        result["reverse_search"] = {
            "google_lens":  "https://lens.google.com/",
            "tineye":       "https://tineye.com/",
            "yandex":       "https://yandex.com/images/",
            "bing_visual":  "https://www.bing.com/visualsearch",
            "pimeyes":      "https://pimeyes.com/en",
            "facecheck_id": "https://facecheck.id/",
            "search4faces": "https://search4faces.com/",
            "note":         "Upload image on these sites to find matching faces"
        }

        # Cleanup
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

        # Risk Score
        risk = 0
        if result["face_detected"]:                       risk += 20
        if result["face_count"] > 1:                      risk += 10
        if result["deepfake_check"].get("suspected"):     risk += 40
        if result["deepfake_check"].get("score",0) > 50: risk += 30

        result["risk_score"] = min(100, risk)
        result["risk_level"] = (
            "CRITICAL" if risk >= 75 else
            "HIGH"     if risk >= 50 else
            "MEDIUM"   if risk >= 25 else
            "LOW"
        )

    except Exception as e:
        result["error"] = str(e)

    return result
