import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, jsonify
from flaskblog import app, db, bcrypt
from flaskblog.forms import RegistrationForm, LoginForm, UpdateAccountForm, ArticleForm
from flaskblog.models import User, Article
from flask_login import login_user, current_user, logout_user, login_required


@app.route('/article', methods=['GET'])
@token_required
def get_articles(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)

    return jsonify({'todos' : output})
@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_article():
    form = ArticleForm()
    if form.validate_on_submit():
        post = Article(title=form.title.data, body=form.body.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your article has been created!', 'success')
        return redirect(url_for('home'))
    #  return render_template('create_post.html', title='New Post',
    #                        form=form, legend='NewPost')


@app.route("/post/<int:article_id>")
def post(article_id):
    article = Article.query.get_or_404(article_id)
    # return render_template('post.html', title=article.title, post=post)
   
    # post_data = {}
    # post_data['title']= article.title
    # post_data['body']= article.body
    # post_data['creationDate']= article.creationDate
    # post_data['user_id']= article.user_id

    return jsonify(article.as_dict())
    # print(article)

@app.route("/post/<int:article_id>/update", methods=['GET', 'POST'])
# @login_required
def update_article(article_id):
    article = Article.query.get_or_404(article_id)
    if article.author != current_user:
        abort(403)
    form = ArticleForm()
    if form.validate_on_submit():
        article.title = form.title.data
        article.body = form.body.data
        db.session.commit()
        flash('Your article has been updated!', 'success')
        return redirect(url_for('post', article_id=article.id))
    elif request.method == 'GET':
        form.title.data = article.title
        form.body.data = article.body
    # return render_template('create_post.html', title='Update Post',
    #                        form=form, legend='Update Post')


@app.route("/post/<int:article_id>/delete", methods=['DELETE'])
# @login_required
def delete_article(article_id):
    article = Article.query.get_or_404(article_id)
    if article.author != current_user:
        abort(403)
    db.session.delete(article)
    db.session.commit()


    return jsonify({ 'message' : 'success'})
    # flash('Your post has been deleted!', 'success')
    # return redirect(url_for('home'))