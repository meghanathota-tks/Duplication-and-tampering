import streamlit as st
import numpy as np
import cv2
import hashlib
from PIL import Image
import imagehash
from skimage.metrics import structural_similarity as ssim

st.set_page_config(layout="wide")
st.title("Image Duplication & Tampering Detection")

# -----------------------------
# SHA256 Hash
# -----------------------------
def generate_sha256(image):

    img_bytes = image.tobytes()
    return hashlib.sha256(img_bytes).hexdigest()


# -----------------------------
# Perceptual Hash Similarity
# -----------------------------
def phash_similarity(img1,img2):

    pil1 = Image.fromarray(img1)
    pil2 = Image.fromarray(img2)

    hash1 = imagehash.phash(pil1)
    hash2 = imagehash.phash(pil2)

    return hash1 - hash2


# -----------------------------
# Tampering Detection
# -----------------------------
def detect_tampering(img1,img2):

    img2 = cv2.resize(img2,(img1.shape[1],img1.shape[0]))

    gray1 = cv2.cvtColor(img1,cv2.COLOR_BGR2GRAY)
    gray2 = cv2.cvtColor(img2,cv2.COLOR_BGR2GRAY)

    diff = cv2.absdiff(gray1,gray2)

    _,thresh = cv2.threshold(diff,20,255,cv2.THRESH_BINARY)

    kernel = np.ones((3,3),np.uint8)
    thresh = cv2.dilate(thresh,kernel,iterations=2)

    contours,_ = cv2.findContours(thresh,cv2.RETR_EXTERNAL,cv2.CHAIN_APPROX_SIMPLE)

    tampered_regions=[]
    boxes=[]

    h,w = img1.shape[:2]

    for cnt in contours:

        area=cv2.contourArea(cnt)

        if area>80:

            x,y,wc,hc=cv2.boundingRect(cnt)

            boxes.append((x,y,wc,hc))

            cx=x+wc//2
            cy=y+hc//2

            if cx<w/2 and cy<h/2:
                tampered_regions.append("Left Upper")

            elif cx>w/2 and cy<h/2:
                tampered_regions.append("Right Upper")

            elif cx<w/2 and cy>h/2:
                tampered_regions.append("Left Lower")

            else:
                tampered_regions.append("Right Lower")

    tampered_regions=list(set(tampered_regions))

    return tampered_regions,boxes,thresh


# -----------------------------
# Highlight Tampering
# -----------------------------
def highlight_tampering(image,boxes):

    img=image.copy()

    for (x,y,w,h) in boxes:
        cv2.rectangle(img,(x,y),(x+w,y+h),(255,0,0),3)

    return img


# -----------------------------
# Upload Images
# -----------------------------
col1,col2=st.columns(2)

with col1:
    file1=st.file_uploader("Upload Image 1",type=["jpg","png","jpeg"])

with col2:
    file2=st.file_uploader("Upload Image 2",type=["jpg","png","jpeg"])


if file1 and file2:

    img1=np.array(Image.open(file1).convert("RGB"))
    img2=np.array(Image.open(file2).convert("RGB"))

    col1,col2=st.columns(2)

    with col1:
        st.image(img1,caption="Image 1")

    with col2:
        st.image(img2,caption="Image 2")


    # -----------------------------
    # Generate SHA256 Hash
    # -----------------------------
    sha1=generate_sha256(img1)
    sha2=generate_sha256(img2)

    with st.status("Running Image Security Checks...",expanded=True):

        # -----------------------------
        # DUPLICATE CHECK
        # -----------------------------
        st.write("🔐 Checking Duplicate Images")

        duplicate=False

        if sha1==sha2:

            duplicate=True
            st.success("Duplicate Images Detected")

        else:

            st.warning("Images are not exact duplicates")


        # -----------------------------
        # SIMILARITY CHECK
        # -----------------------------
        similar_images = False

        if not duplicate:
            distance = phash_similarity(img1,img2)
            if distance > 25:
                st.error("Images are not related or similar")
                st.info("Tampering detection skipped")
            else:
                similar_images = True
                st.write("🛡 Checking Tampering")
                tampered_regions,boxes,mask = detect_tampering(img1,img2)
                if len(tampered_regions)==0:
                    st.success("No Tampering Detected")
                else:
                    st.error("Tampering Detected")
                    st.write("Tampered Areas:")
                    for r in tampered_regions:
                        st.write("•",r)


    # -----------------------------
    # Tampering Analysis Button
    # -----------------------------
    if not duplicate and similar_images:

        if st.button("View Tampered Analysis"):

            tampered_regions,boxes,mask=detect_tampering(img1,img2)

            highlighted=highlight_tampering(img2,boxes)

            st.subheader("Tampered Areas Highlighted")
            st.image(highlighted,use_container_width=True)

            st.subheader("Tampered Pixel Mask")
            st.image(mask,use_container_width=True)


    # -----------------------------
    # HASH VALUE BUTTON
    # -----------------------------
    @st.dialog("SHA256 Hash Values")
    def show_hash():

        st.write("Image 1 Hash")
        st.code(sha1)

        st.write("Image 2 Hash")
        st.code(sha2)

    if st.button("View Hash Value"):
        show_hash()