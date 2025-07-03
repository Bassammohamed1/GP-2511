from flask import Flask, request, jsonify
import tensorflow as tf
from tensorflow.keras.models import load_model
from PIL import Image
import numpy as np
import os

app = Flask(__name__)

# Load both models
model1_path = 'model/bassam1_model.h5'  # First model
model2_path = 'model/bassam2_model.h5'  # Second model for character recognition
model1 = load_model(model1_path)
model2 = load_model(model2_path)

# Preprocessing function
def preprocess_image(image):
    image = image.convert('RGB')  # Convert to RGB if the image has a different mode
    image = image.resize((299, 299))  # Resize to the expected input size for the first model
    image = np.array(image)
    image = image.astype('float32') / 255.0  # Normalize pixel values
    image = np.expand_dims(image, axis=0)  # Add batch dimension
    return image

# Preprocessing for character model
def preprocess_for_character_model(image):
    image = image.convert('L')  # Convert to grayscale for the character model (assuming it expects grayscale)
    image = image.resize((28, 28))  # Resize to the expected input size for the second model
    image = np.array(image)
    image = image.astype('float32') / 255.0
    image = np.expand_dims(image, axis=0)  # Add batch dimension
    image = np.expand_dims(image, axis=-1)  # Add channel dimension if needed
    return image

@app.route('/predict', methods=['POST'])
def predict():
    if 'image' not in request.files:
        return jsonify({'error': 'No image provided'}), 400

    image_file = request.files['image']
    if image_file.filename == '':
        return jsonify({'error': 'No image selected for uploading'}), 400

    try:
        # Save the image to the uploads directory
        filepath = os.path.join('uploads', image_file.filename)
        image_file.save(filepath)

        # Load and preprocess the image for the first model
        image = Image.open(filepath)
        image_for_model1 = preprocess_image(image)

        # Make prediction with the first model
        prediction = model1.predict(image_for_model1)
        predicted_class = np.argmax(prediction, axis=1)[0]

        # If the first model returns "0 / Normal"
        if predicted_class == 0:
            # Preprocess the image for the second model
            image_for_model2 = preprocess_for_character_model(image)

            # Make prediction with the second model
            char_prediction = model2.predict(image_for_model2)
            predicted_char = np.argmax(char_prediction, axis=1)[0]  # Assuming the second model returns the index of the character

            # Delete the uploaded file after prediction
            os.remove(filepath)

            # Return the result from the second model
            return jsonify({'prediction': 'Normal', 'character': chr(predicted_char + 65)})  # Assuming A=0, B=1, ...

        else:
            # If the first model returns "1", return it directly
            os.remove(filepath)
            return jsonify({'prediction': 'Reversal'})  # Reversal corresponds to class 1

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000)
