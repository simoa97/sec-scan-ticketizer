from flask import Flask, jsonify
from flask_swagger_ui import get_swaggerui_blueprint

app = Flask(__name__)

# Sample API endpoint
@app.route('/')
def index():
    """
    This is the root endpoint.

    Returns:
        str: Welcome message.
    """
    return "Welcome to my Flask API!"

# Another sample API endpoint
@app.route('/api/data')
def get_data():
    """
    This endpoint returns some sample data.

    Returns:
        dict: Sample data.
    """
    data = {"message": "This is some data from the API"}
    return jsonify(data)

# Generate Swagger JSON dynamically
@app.route('/swagger.json')
def swagger_json():
    """
    This endpoint generates the Swagger JSON specification.

    Returns:
        dict: Swagger JSON specification.
    """
    swagger_data = {
        "openapi": "3.0.0",
        "info": {
            "title": "Flask API",
            "version": "1.0"
        },
        "paths": {
            "/": {
                "get": {
                    "summary": "Welcome message",
                    "responses": {
                        "200": {
                            "description": "Welcome message"
                        }
                    }
                }
            },
            "/api/data": {
                "get": {
                    "summary": "Get sample data",
                    "responses": {
                        "200": {
                            "description": "Sample data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "message": {
                                                "type": "string"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return jsonify(swagger_data)

# Swagger UI setup
SWAGGER_URL = '/api/docs'  # URL for exposing Swagger UI (without trailing '/')
API_URL = '/swagger.json'  # Our API url
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': "Flask API"
    },
)
app.register_blueprint(swaggerui_blueprint)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
    app.run(debug=True, host='0.0.0.0')
