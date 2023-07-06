from flask import Flask, request
from flask_restx import Resource
from flask_cors import CORS
from appModels.formsNamespaces import rest_api, login_namespace
from appModels.loginFormsModels import login_model
from background.authenticaction import login, is_valid_token_exists_token, block_token
from background.logsconf import logger
from appModels.docModelsNamespaces import FailureModel, SuccessModel, SuccessDataModelUserToken
from appModels.models import Base
from background.config import BaseConfig
def create_app():

    app = Flask(__name__)
    app.secret_key = BaseConfig.SECRET_KEY
    rest_api.init_app(app)
    CORS(app)
    with app.app_context():
        Base.metadata.create_all(BaseConfig.engine)
        logger.info("start app")

    return app


app = create_app()

@login_namespace.route('/login')
class Login(Resource):
    """
    Endpoint obsługujący operacje związane z logowaniem.
    """
    @login_namespace.doc(
        responses={
            200: ('Successful operation', SuccessDataModelUserToken),
            400: ('Bad Request', FailureModel),
            422: ('Unprocessable entity', FailureModel),
            500: ('Server Error', FailureModel),
        }
    )
    @rest_api.expect(login_model, validate=True)
    def post(self):
        """
        Loguje użytkownika do systemu

        Zwraca wiadomość wraz z danymi o wyniku próby logowania.
        """
        req_data = request.get_json()
        _username = req_data.get("username").lower()
        _password = req_data.get("password")
        if not all([_username, _password]):
            return {"success": False, "msg": "Failed to validate required data"}, 422

        response = login(_username, _password)
        if response['success'] == True:
            logger.info(
                '[%s] -- logged in success', _username)
            return response, 200
        else:
            logger.info(
                '[%s] -- logged in failed', _username)
            return response, 500
        


@login_namespace.route('/logout')
class LogoutUser(Resource):
    """
    Klasa reprezentująca zasób wylogowania użytkownika.

    Metody:
    post: Wylogowuje użytkownika, dodając jego token JWT do listy zablokowanych tokenów.
    """
    @login_namespace.doc(
        responses={
            200: ('Successful operation', SuccessModel),
            400: ('Bad Request', FailureModel),
            401: ('Unauthorized', FailureModel),
            500: ('Server Error', FailureModel),
        }
    )
    def post(self):
        """
        Wylogowywuje użytkownika z systemu

        Zwraca wiadomość o wyniku próby wylogowania.
        """
        _jwt_token = request.headers.get("authorization")
        if _jwt_token and is_valid_token_exists_token(_jwt_token):
            response = block_token(_jwt_token)
            return response

        else:
            return {"success": False, "msg": "Valid JWT token is missing"}, 401


if __name__ == "__main__":
    app.run()
