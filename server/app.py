#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class ClearSession(Resource):
    def delete(self):
        session['page_views'] = None
        session['user_id'] = None
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')
        image_url = json.get('image_url')
        bio = json.get('bio')

        errors = {}

        if not username:
            errors['username'] = 'Username is required.'
        if not password:
            errors['password'] = 'Password is required.'
        
        if errors:
            return jsonify(errors), 422

        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )

        try:
            user.password_hash = password
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }), 201
        except IntegrityError:
            db.session.rollback()
            return jsonify({'username': 'Username must be unique.'}), 422



class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return jsonify({
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }), 200
        return jsonify({'message': 'Unauthorized'}), 401

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }), 200
        return jsonify({'message': 'Invalid credentials'}), 401


class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id')
            return {}, 204
        return jsonify({'message': 'Unauthorized'}), 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            recipes = Recipe.query.all()
            return jsonify([recipe.to_dict() for recipe in recipes]), 200
        return jsonify({'message': 'Unauthorized'}), 401

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'message': 'Unauthorized'}), 401
        
        json_data = request.get_json()
        title = json_data.get('title')
        instructions = json_data.get('instructions')
        minutes_to_complete = json_data.get('minutes_to_complete')

        errors = {}

        if not title:
            errors['title'] = 'Title is required.'
        if not instructions:
            errors['instructions'] = 'Instructions are required.'
        if not minutes_to_complete:
            errors['minutes_to_complete'] = 'Minutes to complete is required.'

        if errors:
            return jsonify(errors), 422

        recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=user_id
        )

        try:
            db.session.add(recipe)
            db.session.commit()
            return jsonify(recipe.to_dict()), 201
        except IntegrityError:
            db.session.rollback()
            return jsonify({'message': 'Error saving the recipe.'}), 422



api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)