from flask import Flask, request, jsonify
import tensorflow as tf
import numpy as np
from PIL import Image
import os

app = Flask(__name__)

# Load the MNIST model
model = tf.keras.models.load_model('model/for_nums_model (1).h5')

# Create an uploads folder if it doesn't exist
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/predict', methods=['POST'])
def predict():
    # Log the incoming files
    print(f"Received files: {request.files}")

    if 'image' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['image']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        # Save the uploaded file to the uploads folder
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        # Process the image
        image = Image.open(file_path).convert('L')  # Convert to grayscale
        image = image.resize((28, 28))             # Resize to 28x28 pixels
        image_array = np.array(image) / 255.0      # Normalize to range [0, 1]
        image_array = image_array.reshape(1, 28, 28, 1)  # Add batch and channel dimensions

        # Make a prediction
        prediction = model.predict(image_array)
        predicted_class = np.argmax(prediction, axis=1)[0]  # Get the class with highest probability

        return jsonify({"predicted_class": int(predicted_class)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=3000)
