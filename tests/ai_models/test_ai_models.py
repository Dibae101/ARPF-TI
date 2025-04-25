"""
Test script for AI models functionality in ARPF-TI.
"""
import os
import unittest
import pickle
import tempfile
import uuid
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile

# Import needed modules
from threat_intelligence.models import AIClassifierModel

class AIModelTests(TestCase):
    """Tests for the AIClassifierModel model and related functionality."""

    def setUp(self):
        """Set up test data."""
        # Create a temporary model file
        self.temp_model_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pkl')
        
        # Create a simple mock model for testing (a basic dictionary in this case)
        mock_model = {
            'name': 'test_model',
            'version': '1.0',
            'features': ['ip', 'domain', 'url'],
            'weights': [0.8, 0.6, 0.7]
        }
        
        # Save to pickle file
        pickle.dump(mock_model, self.temp_model_file)
        self.temp_model_file.close()
        
        # Create a test AI model entry
        self.model = AIClassifierModel.objects.create(
            name='Test Classifier',
            model_type='random_forest',
            description='A test classifier model',
            file_path=self.temp_model_file.name,
            model_params={
                'sklearn_module': 'sklearn.ensemble.RandomForestClassifier',
                'feature_names': ['ip_length', 'domain_parts', 'tld_type']
            },
            is_active=True
        )
    
    def tearDown(self):
        """Clean up after tests."""
        # Remove the temporary file
        if os.path.exists(self.temp_model_file.name):
            os.unlink(self.temp_model_file.name)
    
    def test_model_creation(self):
        """Test that an AIClassifierModel is created correctly."""
        self.assertEqual(self.model.name, 'Test Classifier')
        self.assertEqual(self.model.model_type, 'random_forest')
        self.assertTrue(self.model.is_active)
        
    def test_model_str_representation(self):
        """Test the string representation of an AIClassifierModel."""
        self.assertTrue('Test Classifier' in str(self.model))
        
    def test_model_file_access(self):
        """Test that the model file can be accessed."""
        self.assertTrue(os.path.exists(self.model.file_path))
        
        # Try to load the model file
        with open(self.model.file_path, 'rb') as f:
            loaded_model = pickle.load(f)
        
        # Verify that the loaded model matches the saved one
        self.assertEqual(loaded_model['name'], 'test_model')
        self.assertEqual(loaded_model['version'], '1.0')
        self.assertEqual(loaded_model['features'], ['ip', 'domain', 'url'])
    
    def test_model_params(self):
        """Test model parameter handling."""
        self.assertEqual(self.model.model_params['sklearn_module'], 
                         'sklearn.ensemble.RandomForestClassifier')
        self.assertEqual(self.model.model_params['feature_names'], 
                         ['ip_length', 'domain_parts', 'tld_type'])

# Additional test class for model file uploads
class AIModelUploadTests(TestCase):
    """Tests for uploading and managing AI model files."""
    
    def setUp(self):
        """Set up test data."""
        # Create a directory for test model files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a simple mock model for testing
        self.mock_model = {
            'name': 'upload_test_model',
            'version': '1.0',
            'features': ['ip', 'domain', 'url'],
            'weights': [0.8, 0.6, 0.7]
        }
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            pickle.dump(self.mock_model, f)
            self.temp_file_path = f.name
    
    def tearDown(self):
        """Clean up after tests."""
        # Remove the temporary file
        if os.path.exists(self.temp_file_path):
            os.unlink(self.temp_file_path)
        
        # Clean up test directory and any files in it
        for file in os.listdir(self.test_dir):
            os.unlink(os.path.join(self.test_dir, file))
        os.rmdir(self.test_dir)
    
    def test_model_file_upload(self):
        """Test uploading a model file."""
        # Simulate file upload
        with open(self.temp_file_path, 'rb') as f:
            file_content = f.read()
        
        uploaded_file = SimpleUploadedFile(
            name="test_model.pkl",
            content=file_content,
            content_type="application/octet-stream"
        )
        
        # Generate a unique filename for the uploaded file
        file_name = f"{uuid.uuid4()}_test_model.pkl"
        file_path = os.path.join(self.test_dir, file_name)
        
        # Save the uploaded file
        with open(file_path, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
        
        # Create model entry
        model = AIClassifierModel.objects.create(
            name='Uploaded Test Model',
            model_type='custom',
            description='A test uploaded model',
            file_path=file_path,
            model_params={
                'custom_module': 'custom_classifier',
                'custom_class': 'CustomClassifier'
            },
            is_active=True
        )
        
        # Verify the model was created
        self.assertEqual(model.name, 'Uploaded Test Model')
        self.assertTrue(os.path.exists(model.file_path))
        
        # Try to load the uploaded model
        with open(model.file_path, 'rb') as f:
            loaded_model = pickle.load(f)
        
        # Verify the loaded model matches the original
        self.assertEqual(loaded_model['name'], 'upload_test_model')
        self.assertEqual(loaded_model['version'], '1.0')

# Manual test function to run outside of Django test runner
def run_manual_tests():
    """Run manual tests that load and use the AI models."""
    from tests import setup_django_test_environment
    setup_django_test_environment()
    
    print("=== Testing AI Model Loading and Usage ===")
    
    # Get all active models
    models = AIClassifierModel.objects.filter(is_active=True)
    print(f"Found {models.count()} active AI models")
    
    for model in models:
        print(f"\nTesting model: {model.name} ({model.model_type})")
        
        try:
            # Check if the model file exists
            if os.path.exists(model.file_path):
                print(f"✓ Model file exists at {model.file_path}")
                
                # Try to load the model
                with open(model.file_path, 'rb') as f:
                    loaded_model = pickle.load(f)
                print(f"✓ Successfully loaded model from {model.file_path}")
                
                # Print model info if available
                if isinstance(loaded_model, dict) and 'name' in loaded_model:
                    print(f"✓ Model info: {loaded_model.get('name')}, version: {loaded_model.get('version', 'N/A')}")
                else:
                    print(f"✓ Model loaded successfully (type: {type(loaded_model).__name__})")
            else:
                print(f"✗ Model file not found at {model.file_path}")
        except Exception as e:
            print(f"✗ Error loading model: {str(e)}")

if __name__ == '__main__':
    # Run Django tests if called directly
    if os.environ.get('RUN_MANUAL_TESTS') == '1':
        run_manual_tests()
    else:
        # Run the Django tests
        unittest.main()