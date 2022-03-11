'use strict';

window.activePathName = location.pathname.match(new RegExp('([a-zA-Z-]+)\.html'))?.[1];

function escapeTags (text) {
    return typeof text === 'string'
        ? text.replace(/</g, '&lt;').replace(/>/g, '&gt;')
        : '';
}

// NAV BAR

jQuery('.navbar-target').append(`<div class="container">
      <div class="navbar-header">
        <button type="button" class="navbar-toggle collapsed" data-toggle="collapse"
                data-target="#bs-example-navbar-collapse-1">
          <span class="sr-only">Toggle navigation</span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
        </button>
        <a class="navbar-brand brand-en" href="./"></a>
      </div>
      <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
        <ul class="nav navbar-nav navbar-right">
          <li><a href="${window.enLanguageLink || 'ru'}">${window.enLanguageLabel || 'RU'}</a></li>
        </ul>
      </div>
    </div>`);

// SIDE MENU

(function($) {
    const items = [{
        name: 'beginning',
        label: 'Beginning',
        ru: 'Начало'
    }, {
        name: 'environment-setting',
        label: 'Environment setting',
        ru: 'Настройка окружения'
    }, {
        name: 'application-class',
        label: 'Application class',
        ru: 'Класс приложения'
    }, {
        name: 'default-configuration',
        label: 'Default configuration',
        ru: 'Конфигурация по умолчанию'
    }, {
        name: 'startup-script',
        label: 'Startup script',
        ru: 'Скрипты запуска'
    }, {
        name: 'primary-init',
        label: 'Primary init',
        ru: 'Первичная инициализация'
    }, {
        name: 'logging',
        label: 'Logging',
        ru: 'Логирование'
    }, {
        header: 'Public part',
        ru: 'Публичная часть'
    }, {
        name: 'first-controller',
        label: 'First controller',
        ru: 'Первый контроллер'
    }, {
        name: 'view',
        label: 'View',
        ru: 'Представление'
    }, {
        name: 'error-handling',
        label: 'Error handling',
        ru: 'Обработка ошибок'
    }, {
        name: 'database',
        label: 'Database',
        ru: 'База данных'
    }, {
        name: 'user-model',
        label: 'User model',
        ru: 'Модель пользователя'
    }, {
        name: 'sign-up-form',
        label: 'Sign up form',
        ru: 'Форма регистрации'
    }, {
        name: 'sign-in-form',
        label: 'Sign in form',
        ru: 'Форма входа'
    }, {
        name: 'security-controller',
        label: 'Security controller',
        ru: 'Контроллер безопасности'
    }, {
        name: 'photo-model',
        label: 'Photo model',
        ru: 'Модель фото'
    }, {
        name: 'comment-model',
        label: 'Comment model',
        ru: 'Модель комментария'
    }, {
        name: 'tag-model',
        label: 'Tag model',
        ru: 'Модель метки'
    }, {
        name: 'article-model',
        label: 'Article model',
        ru: 'Модель статьи'
    }, {
        name: 'article-controller',
        label: 'Article controller',
        ru: 'Контроллер статьи'
    }, {
        name: 'access-control',
        label: 'Access control',
        ru: 'Права доступа'
    }, {
        header: 'Administration',
        ru: 'Администрирование'
    }, {
        name: 'admin-module',
        label: 'Admin module',
        ru: 'Модуль администрирования'
    }, {
        name: 'admin-access',
        label: 'Module access',
        ru: 'Доступ к модулю'
    }, {
        name: 'admin-user-model',
        label: 'User model',
        ru: 'Модель пользователя'
    }, {
        name: 'admin-file-model',
        label: 'File model',
        ru: 'Модель файла'
    }, {
        name: 'admin-photo-model',
        label: 'Photo model',
        ru: 'Модель фото'
    }, {
        name: 'admin-comment-model',
        label: 'Comment model',
        ru: 'Модель комментария'
    }, {
        name: 'admin-tag-model',
        label: 'Tag model',
        ru: 'Модель метки'
    }, {
        name: 'admin-article-model',
        label: 'Article model',
        ru: 'Модель статьи'
    }, {
        name: 'admin-base-controller',
        label: 'Base controller',
        ru: 'Базовый контроллер'
    }, {
        name: 'admin-crud-controller',
        label: 'CRUD controller'
    }, {
        name: 'admin-user-controller',
        label: 'User controller',
        ru: 'Контроллер пользователя'
    }, {
        name: 'admin-article-controller',
        label: 'Article controller',
        ru: 'Контроллер статьи'
    }, {
        name: 'admin-file-controller',
        label: 'File controller',
        ru: 'Контроллер файла'
    }, {
        name: 'admin-photo-controller',
        label: 'Photo controller',
        ru: 'Контроллер фото'
    }];
    const lang = document.documentElement.lang;
    const result = [];
    for (const item of items) {
        if (item.header) {
            const label = item[lang] || item.header;
            result.push(`<li class="nav-header"><a>${label}</a></li>`);
        } else {
            const active = item.name === activePathName ? 'active' : '';
            const label = item[lang] || item.label;
            result.push(`<li class="${active}"><a href="${item.name}.html">${label}</a></li>`);
        }
    }
    $('article > .row').append(
`<div class="col-md-3">
  <hr class="hidden-lg hidden-md">
  <ul class="side-menu nav nav-pills nav-stacked">${result.join('')}</ul>
</div>`);
})(jQuery);

// CODES

(function($) {
    const codes = {
        'environment-setting': [`{
  "name": "areto-blog",
  "version": "1.0.0",
  "description": "Areto Framework Demo App",
  "license": "MIT",
  "dependencies": {
    "areto": "^3.1.0",
    "areto-ejs": "^1.0.0",
    "multer": "^1.4.0",
    "sharp": "~0.29.0"
  }
}`, `cd /areto-blog
npm install`],
        'application-class': [`const Base = require('areto/base/Application');
module.exports = class Blog extends Base {
};
module.exports.init(module);`],
        'default-configuration': [`module.exports = {
  port: 8888
};`, `module.exports = {
  parent: 'default',
  port: 3000
};`],
        'startup-script': [`(async ()=> {
  const Application = require('../Application');
  const application = new Application;
  try {
    await application.init();
    await application.start();
  } catch (err) {
    application.logError(err);
    process.exit();
  }
})();`, `{
  "configurations": [{
    "type": "node",
    "request": "launch",
    "name": "Start app",
    "program": "\${workspaceFolder}/console/start.js",
    "env": {
      "NODE_ENV": "development"
    }
  },{
    "type": "node",
    "request": "launch",
    "name": "Init app",
    "program": "\${workspaceFolder}/console/init.js",
    "env": {
      "NODE_ENV": "development"
    }
  }]
}`, `info: Configured as development.default
info: Blog app is attached to / 
info: Starting server...  
info: Server is running on port 3000`],
        'primary-init': [`(async ()=> {
  const SystemHelper = require('areto/helper/SystemHelper');
  const Migrator = require('areto/db/Migrator');
  const Application = require('../Application');
  const application = new Application;
  try {
    const data = SystemHelper.parseArguments(process.argv);
    await application.init();
    const migrator = new Migrator({module: application});
    await migrator.migrate(data.action, data.file);
  } catch (err) {
    application.logError('Migration error', err);
  }
  process.exit();
})();`, `const Base = require('areto/db/Migration');
module.exports = class Init extends Base {
  async apply () {
    await this.getDb().createIndex('user', [{email: 1}, {unique: true}]);
    const user = this.spawn(User);
    user.setAttrs({
      name: 'Administrator',
      email: 'a@a.a',
      role: 'admin',
      password: '123456'
    });
    await user.save();
  }
};`, `node console/init.js apply migrations/Init`, `Name: Init Areto Blog
Working directory: areto-blog
Javascript file: console/init.js
Application parameters: apply migrations/Init`],
        'logging': [`{  
  components: {
    'logger': {
      level: 'info'
    }
  }
};`, `{  
  parent: 'default',
  components: {    
    'logger': {
      level: 'trace'
    }
  }
};`],
        'first-controller': [`const Base = require('areto/base/Controller');
module.exports = class DefaultController extends Base {
  actionIndex () {
    this.send('&lt;h1>Hello blog!&lt;/h1>');
  }
};
module.exports.init(module);`],
        'view': [`{  
  components: {    
    'viewEngine': {
      engine: require('areto-ejs'),
      extension: 'ejs'
    }
  }
};`, `<% layout(view.get('_layouts/content')) -%>
<p>Hello blog!</p>`, `// include layout to the top-level layout
<% layout(view.get('_layouts/main')) -%>
<div class="row">
  <div class="col-sm-8">
    <%- body -%>
  </div>
</div>`, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Areto Blog
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"
     integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
</head>
<body>
<div class="wrapper">
  <nav class="navbar-inverse navbar-fixed-top navbar" role="navigation">
     <div class="container">
        <div class="navbar-header">
           <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#topnav-collapse">
              <span class="sr-only">Toggle navigation</span>
              <span class="icon-bar"></span>
              <span class="icon-bar"></span>
              <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="/">ARETO Blog</a>
        </div>
     </div>
  </nav>
  <div class="container">
    <%- body -%>
  </div>
</div>
  <script src="https://code.jquery.com/jquery-2.2.4.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"
     integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
  </body>
</html>`, `actionIndex () {
  this.render("index");
}`],
        'error-handling': [`{  
  router: {
    'errors': {
        controller: 'default',
        action: 'error'
    }
  }
};`, `actionError () {
  // returned HTTP error code (404, 403, 500)
  this.setStatus(this.err.status);
  // select the template corresponding error code
  switch (this.err.status) {
    case 403:
    case 404:
      this.render(this.err.status);
      break;
    default:
      this.render(500);
}`, `<% layout(view.get('_layouts/main')) -%>
<div class="row">
  <div class="col-sm-8 col-sm-offset-2 col-lg-6 col-lg-offset-3">
    <div class="error-page">
      <div class="text-center">
        <h1 class="text-danger">Access is denied</h1>
        <p>Access is restricted to authorized users.</p>
      </div>
    </div>
  </div>
</div>`, `<% layout(view.get('_layouts/main')) -%>
<div class="row">
  <div class="col-sm-8 col-sm-offset-2 col-lg-6 col-lg-offset-3">
    <div class="error-page">
      <div class="text-center">
        <h1 class="text-danger">Page not found</h1>
        <p>We did not find the page you requested.</p>
      </div>
    </div>
  </div>
</div>`, `<% layout(view.get('_layouts/main')) -%>
<div class="row">
  <div class="col-sm-8 col-sm-offset-2 col-lg-6 col-lg-offset-3">
    <div class="error-page">
      <div class="text-center">
        <h1 class="text-danger">Server error</h1>
        <p>We are working to resolve this problem now.</p>
      </div>
    </div>
  </div>
</div>`],
        'database': [`{  
  components: {    
    'db': {
      Class: 'areto/db/MongoDatabase',
      settings: {
        host: 'localhost',
        port: 27017,
        database: 'areto-basic'
      }
    }
  }
};`, `info: MongoDatabase: Connection is opening: mongodb://localhost:27017/areto-blog 
info: MongoDatabase: Connection is open `],
        'user-model': [`const Base = require('areto/db/ActiveRecord');
        
module.exports = class User extends Base {
  
};
module.exports.init(module);
const SecurityHelper = require('areto/helper/SecurityHelper');`, `static getConstants () {
  return {
    TABLE: 'user',
    ATTRS: [
      'name',
      'email',
      'role',
      'status',
      'passwordHash',
      'authKey'
    ],
    BEHAVIORS: {
      'timestamp': require('areto/behavior/TimestampBehavior')
    },
    STATUS_PENDING: 'penging',
    STATUS_ACTIVE: 'active',
    STATUS_BANNED: 'banned',
    ROLE_READER: 'reader',
    ROLE_AUTHOR: 'author',
    ROLE_EDITOR: 'editor',
    ROLE_MODERATOR: 'moderator',
    ROLE_ADMIN: 'admin',
    AUTH_KEY_LENGTH: 16
  };
}`, `findIdentity (id) {
 return this.findById(id).and({status: this.STATUS_ACTIVE});
}`, `constructor (config) {
  super(config);
  this.set('role', this.ROLE_AUTHOR);
  this.set('status', this.STATUS_ACTIVE);
}`, `getTitle () {
  return this.get('name');
}`, `isActive () {
  return this.get('status') === this.STATUS_ACTIVE;
}

isBanned () {
  return this.get('status') === this.STATUS_BANNED;
}`, `getAssignments () {
  return [this.get('role')];
}`, `async beforeSave (insert) {
  await super.beforeSave(insert);
  this.setPasswordHash();
  if (insert) {
    this.setAuthKey();
  }
}

setAuthKey () {
  this.set('authKey', SecurityHelper.getRandomString(this.AUTH_KEY_LENGTH));
}`, `checkPassword (password) {
  return SecurityHelper.checkPassword(password, this.get('passwordHash'));
}

setPasswordHash () {
  const password = this.get('password');
  if (password) {
    this.set('passwordHash', SecurityHelper.encryptPassword(password));
  }
}`],
        'sign-up-form': [`const Base = require('areto/base/Model');
const User = require('./User');

module.exports = class SignUpForm extends Base {
    
};
module.exports.init(module);`, `static getConstants () {
  return {
    RULES: [
      [['name', 'email', 'password', 'passwordRepeat', 'captchaCode'], 'required'],
      ['name', 'string', {min: 3, max: 24}],
      ['name', 'regexp', {pattern: /^[а-яa-z\\s-]+$/i}],
      ['email', 'email'],
      ['captchaCode', require('areto/captcha/CaptchaValidator'), {
         CaptchaController: require('../controller/AuthController')
      }],
      ['password', 'string', {min: 6, max: 24}],
      ['passwordRepeat', 'compare', {compareAttr: 'password'}],
      [['name', 'email'], 'unique', {
         skipOnAnyError: true,
         targetClass: User,
         ignoreCase: true
      }]
    ],
    ATTR_LABELS: {
      captchaCode: 'Verification code'
    }
  };
}`, `async register () {
  if (await this.validate()) {
    const model = this.spawn(User);
    model.setAttrs(this);
    if (await model.save()) {
      await this.user.login(model, 0);
    } else {
      this.addError('name', model.getFirstError());
    }
  }
}`],
        'sign-in-form': [`const CAPTCHA_SCENARIO = 'captcha';
const Base = require('areto/base/Model');

module.exports = class SignInForm extends Base {
};
module.exports.init(module);

const RateLimit = require('areto/security/rate-limit/RateLimit');
const PasswordAuth = require('../component/auth/PasswordAuth');`, `static getConstants () {
  return {
    RULES: [
      [['email', 'password'], 'required'],
      ['email', 'email'],
      ['password', 'string', {min: 6, max:24}],
      ['rememberMe', 'boolean'],
      ['captchaCode', 'required', {on: [CAPTCHA_SCENARIO]}],
      ['captchaCode', {
        Class: require('areto/security/captcha/CaptchaValidator'),
        on: [CAPTCHA_SCENARIO]
      }]
    ],
    ATTR_LABELS: {
      rememberMe: 'Remember me',
      captchaCode: 'Verification code'
    },
    CAPTCHA_SCENARIO
  };
}`, `async login () {
  await this.validate();
  if (!this.hasError()) {
    const result = await this.createPasswordAuth().login();
    if (result.error) {
        this.addError('email', result.error);
    }
    await this.updateRateLimit();
    this.toggleCaptchaScenario();
  }
}`, `constructor (config) {
  super({
    // user: [new WebUser]
    rateLimit: config.module.get('rateLimit'),
    rateLimitType: 'signIn',
    rememberPeriod: 7 * 24 * 3600,
    ...config
  });
}

createPasswordAuth () {
  return this.spawn(PasswordAuth, {
    email: this.get('email'),
    password: this.get('password'),
    rememberMe: this.get('rememberMe'),
    user: this.user
  });
}

updateRateLimit () {
  if (this._rateLimitModel) {
    if (this.hasError()) {
      await this._rateLimitModel.increment();
    }
    if (this.isCaptchaRequired()) { // captcha has been validated
      await this._rateLimitModel.reset();
    }
  }
}`],
        'security-controller': [`const Base = require('../component/BaseController');
        
module.exports = class AuthController extends Base {
  
  async actionSignUp () {
    ...
  }
  async actionSignIn () {
    ...
  }
  async actionLogout () {
    ...
  }
};
module.exports.init(module);`, `static getConstants () {
  return {
    ACTIONS: {
      'captcha': {
        Class: require('areto/captcha/CaptchaAction'),
        minLength: 3,
        maxLength: 4,
        // fixedVerifyCode: '123'
      }
    },
    BEHAVIORS: {
      'rejectSigned': {
        Class: require('areto/filter/AccessControl'),
        rules: [{
          actions: ['sign-in', 'sign-up'],
          permissions: ['?']
        }],
        deny: (action, user)=> {
          return action.render('signed', {model: user.model});
        }
      }
    }
  };
}`, `async actionSignUp () {
  const model = this.spawn(SignUpForm, {user: this.user});
  if (this.isGet()) {
    return this.render('sign-up', {model});
  }
  model.captchaAction = this.createAction('captcha');
  model.load(this.getPostParams());
  await model.register();
  return model.hasError()
    ? this.render('sign-up', {model})
    : this.goLogin();
}`, `async actionSignIn () {
  const model = this.spawn(SignInForm, {user: this.user});
  await model.resolveCaptchaScenario();
  if (this.isGet()) {
    return this.render('sign-in', {model});
  }
  model.captchaAction = this.createAction('captcha');
  await model.load(this.getPostParams()).login();
  return model.hasError()
    ? this.render('sign-in', {model})
    : this.goBack();
}`, `async actionLogout () {
  await this.user.logout();
  this.goHome();
}`],
        'photo-model': [`const Base = require('areto/db/ActiveRecord');
module.exports = class Photo extends Base {
  static getConstants () {
    return {
      TABLE: 'photo',
      SIZE_LARGE: 720,
      SIZE_MEDIUM: 360,
      SIZE_SMALL: 128
    };
  }

  getTitle () {
    return this.get('title') || '';
  }
};
module.exports.init(module);
const path = require('path');`, `getLarge () {
  return this.getThumb(this.SIZE_LARGE);
}

getMedium () {
  return this.getThumb(this.SIZE_MEDIUM);
}

getSmall () {
  return this.getThumb(this.SIZE_SMALL);
}

getThumb (size) {
  return \`photo/\${size}/\${this.get('filename')}\`;
}`],
        'comment-model': [`const Base = require('areto/db/ActiveRecord');
module.exports = class Comment extends Base {
  static getConstants () {
    return {
      TABLE: 'comment',
      ATTRS: [
        'articleId',
        'name',
        'email',
        'ip',
        'content',
        'status',
        'createdAt',
        'updatedAt'
      ],
      INDEXES: [
        [{entityId: 1}, {unique: false}]
      ],
      RULES: [
        [['name','email','content'], 'required'],
        ['name', 'string', {min: 2, max: 32}],
        ['email', 'email'],
        ['content', 'string', {min: 3, max: 512}]
      ],
      BEHAVIORS: {
        timestamp: require('areto/behaviors/Timestamp')
      },
      STATUS_PENDING: 'pending',
      STATUS_APPROVED: 'approved',
      STATUS_REJECTED: 'rejected'
    };
  }
};
module.exports.init(module);`, `init () {
  super.init();
  this.set('status', this.STATUS_PENDING);
}`, `getTitle () {
  return this.get('content');
}`, `isPending () {
  return this.get('status') === this.STATUS_PENDING;
}

isApproved () {
  return this.get('status') === this.STATUS_APPROVED;
}

isRejected () {
  return this.get('status') === this.STATUS_REJECTED;
}`],
        'tag-model': [`const Base = require('areto/db/ActiveRecord');
module.exports = class Tag extends Base {
  static getConstants () {
    return {
      TABLE: 'tag',
      ATTRS: ['name'],
      RULES: [
        ['name', 'required'],
        ['name', 'string', {min:2, max:32}]
      ]
    };
  }

  getTitle () {
    return this.get('name');
  }
};
module.exports.init(module);
const Article = require('./Article');`, `relArticles () {
  return this.hasMany(Article, Article.PK, 'articleId')
    .and({status: Article.STATUS_PUBLISHED})
    .with('mainPhoto', 'tags')
    .viaTable('rel_article_tag', 'tagId', this.PK);
}`],
        'article-model': [`const Base = require('areto/db/ActiveRecord');
module.exports = class Article extends Base {
  static getConstants () {
    return {
      TABLE: 'article',
      STATUS_DRAFT: 'draft',
      STATUS_PUBLISHED: 'published',
      STATUS_ARCHIVED: 'archived'
    };
  }
};
module.exports.init(module);
const Comment = require('./Comment');
const Photo = require('./Photo');
const User = require('./User');
const Tag = require('./Tag');`, `getTitle () {
  return this.get('title');
}`, `isDraft () {
  return this.get('status') === this.STATUS_DRAFT;
}

isPublished () {
  return this.get('status') === this.STATUS_PUBLISHED;
}

isArchived () {
  return this.get('status') === this.STATUS_ARCHIVED;
}`, `findPublished () {
  return this.find().and({status: this.STATUS_PUBLISHED}).with('mainPhoto','tags');
}`, `findBySearch (text) {
  const query = this.findPublished();
  if (typeof text === 'string' && /[a-z0-9\\-\\s]{1,32}/i.test(text)) {
    query.and(['LIKE', 'title']);
  }
  return query;
}`, `relAuthor () {
  return this.hasOne(User, User.PK, 'authorId');
}`, `relPhotos () {
  return this.hasMany(Photo, 'articleId', this.PK);
}`, `relMainPhoto () {
  return this.hasOne(Photo, Photo.PK, 'mainPhotoId');
}`, `relComments () {
  return this.hasMany(Comment, 'articleId', this.PK).and({
    status: Comment.STATUS_APPROVED
  });
}`, `relTags () {
  return this.hasMany(Tag, Tag.PK, 'tagId').viaTable('rel_article_tag', 'articleId', this.PK);
}`],
        'article-controller': [`const Base = require('../component/BaseController');
        
module.exports = class ArticleController extends Base {
  
};
module.exports.init(module);
const ActiveDataProvider = require('areto/data/ActiveDataProvider');
const Article = require('../model/Article');`, `async actionIndex () {
  const provider = this.createDataProvider({
    query: this.spawn(Article).findPublished()
  });
  await provider.prepare();
  await this.render('index', {provider});
}`, `async actionSearch () {
  const provider = this.createDataProvider({
    query: this.spawn(Article).findBySearch(this.getQueryParam('text'))
  });
  await this.renderDataProvider(provider, 'index', {provider});
}`, `async actionView () {
  const model = await this.getModel({
    with: ['category', 'mainPhoto', 'photos', 'tags']
  });
  const comment = this.spawn(Comment);
  if (this.isGet()) {
    return this.renderView(model, comment);
  }
  comment.load(this.getPostParams());
  comment.set('articleId', model.getId());
  comment.set('ip', this.req.ip);
  await comment.save();
  if (comment.hasError()) {
    return this.renderView(model, comment);
  }
  this.setFlash('comment-done', this.translate('You message has been sent successfully!'));
  this.redirect(['view', model]);
}`, `async renderView (model, comment) {
  const comments = this.createDataProvider({
    query: model.relComments()
  });
  await comments.prepare();
  await this.render('view', {model, comments, comment});
}`, `async actionTagged () {
  const tagName = this.getQueryParam('tag');
  const tag = this.spawn(Tag);
  tag.set('name', tagName);
  if (!await tag.validate()) {
    return this.render('tagged', {tagName});
  }
  const model = await this.spawn(Tag).findByName(tagName).one();
  if (!model) {
    return this.render('tagged', {tagName});
  }
  const provider = this.createDataProvider({
    query: tag.relArticles()
  });
  await this.renderDataProvider(provider, 'tagged', {provider, tagName});
}`],
        'access-control': [`{
  components: {
    rbac: {}
  }  
}`, `module.exports = {
  'updateArticle': {
    type: 'permission'
  },
  'updateOwnArticle': {
    type: 'permission',
    children: ['updateArticle'],
    rule: 'author'
  },
  'reader': {
    type: 'role'
  },
  'author': {
    type: 'role',
    children: ['reader', 'updateOwnArticle']
  },
  'editor': {
    type: 'role',
    children: ['author', 'updateArticle']
  },
  'moderator': {
    type: 'role',
    children: ['author']
  },
  'admin': {
    type: 'role',
    children: ['editor', 'moderator']
  }
};`, `module.exports = {
  author: {
    Class: require('areto/rbac/AuthorRule')
  }
};`, `module.exports = {
  // userId1: ['role1'],
  // userId2: ['role1', 'role2']
};`],
        'admin-module': [`{  
  modules:  {
    'admin': {}
  }
}`],
        'admin-access': [`const Base = require('areto/base/Module');
module.exports = class Admin extends Base {
  static getConstants ()  {
    return {
      BEHAVIORS: {
        access: {
          Class: require('areto/filters/AccessControl'),
          rules: [{
            allow: true,
            permissions: ['reader']
          }]
        }
      }
    };
  }
};
module.exports.init(module);`],
        'admin-user-model': [`const Base = require('../../../model/User');
module.exports = class User extends Base {
  static getConstants () {
    return {
      RULES: [
        [['name', 'email', 'role', 'status'], 'required'],
        ['password', 'required', {on: ['create']}],
        ['status', 'range', {range: [
          this.STATUS_PENDING,
          this.STATUS_ACTIVE,
          this.STATUS_BANNED
        ]}],
        ['role', 'range', {range: [
          this.ROLE_READER,
          this.ROLE_AUTHOR,
          this.ROLE_EDITOR,
          this.ROLE_MODERATOR,
          this.ROLE_ADMIN
        ]}],
        ['name', 'string', {min: 3, max: 24}],        
        ['email', 'email'],
        ['password', 'string', {min: 6, max: 32}],
        [['email', 'name'], 'unique', {ignoreCase: true}]
      ],
      ATTR_VALUE_LABELS: {
        'status': {
          [this.STATUS_ACTIVE]: 'Active',
          [this.STATUS_BANNED]: 'Banned'
        },
        'role': {
          [this.ROLE_READER]: 'Reader',
          [this.ROLE_AUTHOR]: 'Author',
          [this.ROLE_EDITOR]: 'Editor',
          [this.ROLE_MODERATOR]: 'Moderator',
          [this.ROLE_ADMIN]: 'Administrator'
        }
      }
    };
  }
};
module.exports.init(module);
const Article = require('./Article');`, `findBySearch (text) {
  if (!text) {
    return this.find();
  }
  return this.find(['OR',
    ['LIKE','name',\`%\${text}%\`],
    ['LIKE','email',\`%\${text}%\`]
  ]);
}`, `relArticles () {
  return this.hasMany(Article, 'authorId', this.PK);
}`],
        'admin-file-model': [`const Base = require('areto/db/ActiveRecord');
const path = require('path');

module.exports = class File extends Base {

  static getConstants () {
    return {
      TABLE: 'file',
      ATTRS: [
        'userId',
        'originalName',
        'filename',
        'mime',
        'extension',
        'size',
        'ip',
        'createdAt'
      ],
      RULES: [
        ['file', 'required'],
        ['file', 'file']
      ],
      BEHAVIORS: {
        timestamp: {
          Class: require('areto/behaviors/Timestamp'),
          updatedAttr: false
        }
      },
      STORE_DIR: path.join(__dirname, '../uploads/temp')
    };
  }
};
module.exports.init(module);

const fs = require('fs');
const multer = require('multer');
const mkdirp = require('mkdirp');
const CommonHelper = require('areto/helper/CommonHelper');`, `findExpired (elapsedSeconds = 3600) {
  const expired = new Date(Date.now() - parseInt(timeout) * 1000);
  return this.find(['<', 'updatedAt', expired]);
}`, `getTitle () {
  return \`\${this.get('originalName')} (\${this.get('filename')})\`;
}`, `isImage () {
  return this.get('mime').indexOf('image') === 0;
}`, `getPath () {
  return path.join(this.STORE_DIR, this.get('filename'));
}`, `async upload (req, res, user) {
  const uploader = this.createSingleUploader();
  await PromiseHelper.promise(uploader.bind(this, req, res));
  this.populateFileStats(req.file, user);
  this.set('file', this.getFileStats());
  return this.save();
}

createSingleUploader () {
  return multer({
    storage: this.createUploaderStorage()
  }).single('file');
}

createUploaderStorage () {
  return multer.diskStorage({
    destination: this.generateStoreDir.bind(this),
    filename: this.generateFilename.bind(this)
  });
}`, `generateStoreDir (req, file, callback) {
  mkdirp(this.STORE_DIR, err => callback(err, this.STORE_DIR));
}

generateFilename (req, file, callback) {
  callback(null, Date.now().toString() + CommonHelper.getRandom(11, 99));
}`, `populateFileStats (file, req, user) {
  this.setAttrs({
    userId: user.getId(),
    originalName: file.originalname,
    filename: file.filename,
    mime: file.mimetype,
    extension: path.extname(file.originalname).substring(1).toLowerCase(),
    size: file.size,
    ip: req.ip
  });
}`, `getFileStats () {
  return {
    model: this,
    path: this.getPath(),
    size: this.get('size'),
    extension: this.get('extension'),
    mime: this.get('mime')
  };
}`, `async afterDelete () {
  await super.afterDelete();
  fs.unlinkSync(this.getPath());
}
`],
        'admin-photo-model': [`const Base = require('../../../model/Photo');
const path = require('path');

module.exports = class Photo extends Base {

  static getConstants () {
    return {
      TABLE: 'photo',
      ATTRS: [
        'title',
        'filename',
        'articleId'
      ],
      RULES: [
        ['title', 'string', {min: 3, max: 255}],
        ['file', 'required', {on: ['create']}],
        ['file', 'file', {onlyImage: true}],
        ['articleId', 'filter', {filter: 'ObjectId'}],
        ['articleId', 'exist', {
          targetClass: require('./Article'),
          targetAttr: this.PK
        }]
      ],
      BEHAVIORS: {
        photo: {
          Class: require('../component/behaviors/ImageConverter'),
          FileClass: require('./File'),
          filenameAttr: 'filename',
          storeDir: path.join(__dirname, '../uploads/photos'),
          thumbDir: path.join(__dirname, '../../../web/photos'),
          size: 720,
          neededThumbs: [720, 360, 128],
          watermark: {
            720: path.join(__dirname, '../data/photo-watermark.png')
          }
        }
      }
    };
  }
};
module.exports.init(module);

const Article = require('./Article');`, `relArticle () {
  return this.hasOne(Article, Article.PK, 'articleId');
}`],
        'admin-comment-model': [`const Base = require('../../../model/Comment');

module.exports = class Comment extends Base {

  static getConstants () {
    return {
      RULES: this.RULES.concat([
        ['status', 'range', {range: [
          this.STATUS_PENDING,
          this.STATUS_APPROVED,
          this.STATUS_REJECTED
        ]}]
      ]),
      ATTR_VALUE_LABELS: {
        'status': {
          [this.STATUS_PENDING]: 'Pending',
          [this.STATUS_APPROVED]: 'Approved',
          [this.STATUS_REJECTED]: 'Rejected'
        }
      }
    };
  }
};
module.exports.init(module);

const Article = require('./Article');`, `findBySearch (text) {
  if (!text) {
    return this.find();
  }
  return this.find(['OR',
    ['LIKE', 'content', \`%\${text}%\`],
    {name: text},
    {email: text}
  ]);
}`, `relArticle () {
  return this.hasOne(Article, Article.PK, 'articleId');
}`],
        'admin-tag-model': [`const Base = require('../../../model/Tag');

module.exports = class Tag extends Base {

  static getConstants () {
    return {
      RULES: [
        ['name', 'required'],
        ['name', 'filter', {filter: 'trim'}],
        ['name', 'string', {min: 2, max: 32}],
        ['name', 'unique', {ignoreCase: true}]
      ],
      INDEXES: [[{name: 1}, {unique: true}]],
      DELETE_ON_UNLINK: ['articles']
    };
  }
};
module.exports.init(module);

const Article = require('./Article');`, `findByName (name) {
  return this.find({name: new RegExp(\`^\${name}$\`, 'i')});
}`, `findBySearch (text) {
  return text
    ? this.find(['LIKE', 'name', \`%\${text}%\`])
    : this.find();
}`, `relArticles () {
  return this.hasMany(Article, Article.PK, 'articleId').viaTable('rel_article_tag', 'tagId', this.PK);
}`],
        'admin-article-model': [`const Base = require('../../../model/Article');

module.exports = class Article extends Base {

  static getConstants () {
    return {
      ATTRS: [
        'status',
        'authorId',
        'category',
        'date',
        'title',
        'content',
        'mainPhotoId',
        'createdAt',
        'updatedAt'
      ],
      RULES: [
        [['title', 'content', 'status', 'date'], 'required'],
        ['title', 'string', {min: 3, max: 128}],
        ['title', 'unique'],
        ['content', 'string', {min: 10, max: 16128}],
        ['date', 'date'],
        ['category', 'id'],
        ['status', 'range', {range: [
          this.STATUS_DRAFT,
          this.STATUS_PUBLISHED,
          this.STATUS_ARCHIVED,
          this.STATUS_BLOCKED
        ]}],
        ['status', 'default', {value: this.STATUS_DRAFT}],
        ['files', 'safe'],
        ['tags', 'validateTags', {skipOnAnyError: true}]
      ],
      BEHAVIORS: {
        'timestamp': require('areto/behavior/TimestampBehavior')
      },
      DELETE_ON_UNLINK: [
        'comments',
        'photos'
      ],
      UNLINK_ON_DELETE: [
        'tags'
      ],
      ATTR_VALUE_LABELS: {
        'status': {
          [this.STATUS_DRAFT]: 'Draft',
          [this.STATUS_PUBLISHED]: 'Published',
          [this.STATUS_ARCHIVED]: 'Archived',
          [this.STATUS_BLOCKED]: 'Blocked'
        }
      }
    };
  }
};
module.exports.init(module);

const ArrayHelper = require('areto/helper/ArrayHelper');
const Comment = require('./Comment');
const Tag = require('./Tag');
const File = require('./File');
const Photo = require('./Photo');
const User = require('./User');`, `findBySearch (text) {
  const query = this.find();
  if (typeof text === 'string' && /[a-z0-9\\-\\s]{1,32}/i.test(text)) {
    query.and(['LIKE','title', \`%\${text}%\`]);
  }
  return query;
}`, `findToSelect () {
  return this.find().select(['title']).asRaw();
}`, `constructor (config) {
  super(config);
  this.set('status', this.STATUS_DRAFT);
}`, `async beforeValidate () {
  await super.beforeValidate();
  await this.resolveFiles(this.get('files'));
}`, `async afterSave (insert) {
  await super.afterSave(insert);
  await this.createPhotos(this.get('files'));
}`, `async resolveFiles (files) {
  if (files && typeof files === 'string') {
    this.set('files', await File.findById(files.split(',')).all());
    await PromiseHelper.setImmediate();
  }
}`, `createPhotos (files) {
  if (!(files instanceof Array)) {
    return false;
  }
  const photos = [];
  for (const file of files) {
    const photo = await this.createPhoto(file);
    if (photo) {
      photos.push(photo);
    }
    await PromiseHelper.setImmediate();
  }
  if (photos.length && this.get('mainPhotoId')) {
    // set first photo as main
    this.set('mainPhotoId', photos[0].getId());
    this.set('files', null);
    await this.forceSave();
  }
}

async createPhoto (file) {
  const photo = this.spawn(Photo);
  photo.set('articleId', this.getId());
  photo.set('file', file);
  try {
    if (await photo.save()) {
      return photo;
    }
  } catch (err) {
    this.log('error', err);
  }
}`, `async validateTags (attr, params) {
  let items = this.get(attr);
  if (typeof items !== 'string') {
    return;
  }
  items = items.split(',').map(item => item.trim()).filter(item => item);
  items = ArrayHelper.unique(items);
  await this.unlinkAll('tags');
  for (const item of items) {
    await this.resolveTag(item);
  }
}`, `resolveTag (name) {
  let model = await this.spawn(Tag).findByName(name).one();
  if (model) {
    return this.link('tags', model);
  }
  model = this.spawn(Tag);
  model.set('name', name);
  if (await model.save()) {
    await this.link('tags', model);
  }
}`, `relAuthor () {
  return this.hasOne(User, User.PK, 'authorId');
}

relPhotos () {
  return this.hasMany(Photo, 'articleId', this.PK);
}

relMainPhoto () {
  return this.hasOne(Photo, Photo.PK, 'mainPhotoId');
}

relComments () {
  return this.hasMany(Comment, 'articleId', this.PK);
}

relTags () {
  return this.hasMany(Tag, Tag.PK, 'tagId').viaTable('rel_article_tag', 'articleId', this.PK);
}`],
        'admin-base-controller': [`const Base = require('areto/base/Controller');
        
module.exports = class Controller extends Base {
  
};`, `async getModel (params) {
  params = {
    ModelClass: this.getModelClass(),
    id: this.getQueryParam('id'),
    ...params
  };
  if (!MongoHelper.isValidId(params.id)) {
    throw new BadRequest;
  }
  let model = new params.ModelClass({module: this.module});
  model = await model.findById(params.id).with(params.with).one();
  if (!model) {
    throw new NotFound;
  }
  return model;
}

createDataProvider (config) {
  return new ActiveDataProvider({
    controller: this,
    ...config
  });
}

async renderDataProvider (provider, template, data) {
  await provider.prepare();
  await this.render(template, data);
}`, `getReferrer () {
  const url = this.isGet()
    ? this.getHeader('referrer')
    : this.getPostParam('referrer');
  return url ? url : '';
}`, `redirectToReferrer (url = 'index') {
  this.redirect(this.getPostParam('referrer') || url);
}`],
        'admin-crud-controller': [`const Base = require('./Controller');
module.exports = class CrudController extends Base {
  
};`, `async actionCreate () {
  const model = this.spawn(this.getModelClass());
  model.scenario = 'create';
  this.isPost() && await model.load(this.getPostParams()).save()
    ? this.redirectToReferrer()
    : await this.render('create', {model});
}`, `async actionView (params) {
  const model = await this.getModel(params);
  await this.render('view', {model});
}`, `async actionUpdate (params) {
  const model = await this.getModel(params);
  model.scenario = 'update';
  this.isPost() && await model.load(this.getPostParams()).save()
    ? this.redirectToReferrer()
    : await this.render('update', {model});
}`, `async actionDelete (params) {
  const model = await this.getModel(params);
  await model.delete();
  this.isAjax()
    ? this.send(model.getId())
    : this.redirectToReferrer();
}`],
        'admin-user-controller': [`const Base = require('../component/CrudController');

module.exports = class UserController extends Base {

  static getConstants ()  {
    return {
      BEHAVIORS: {
        'access': {
          Class: require('areto/filter/AccessControl'),
          rules: [{
            allow: true,
            permissions: ['admin']
          }]
        }
      }
    };
  }
};
module.exports.init(module);

const User = require('../model/User');`, `async actionIndex () {
  const provider = this.createDataProvider({
    query: this.spawn(User).findBySearch(this.getQueryParam('search')),
    sort: {
      attrs: {
        [User.PK]: true,
        name: true,
        email: true,
        role: true
      },
      defaultOrder: {[User.PK]: -1}
    }
  });
  await this.renderDataProvider(provider, 'index', {provider});
}`],
        'admin-article-controller': [`const Base = require('../component/CrudController');

module.exports = class ArticleController extends Base {

  async renderForm (template, params) {
    await this.render(template, {
      categories: await this.spawn(Category).findNames().all(),
      ...params
    });
  }
};
module.exports.init(module);

const Category = require('../model/Category');
const Article = require('../model/Article');`, `async actionIndex () {
  const searchText = this.getQueryParam('search');
  const query = this.spawn(Article).findBySearch(this.getQueryParam('search')).with('author', 'mainPhoto');
  const provider = this.createDataProvider({
    query: this.spawn(Article).findBySearch(searchText).with('author', 'mainPhoto'),
    pagination: {pageSize: 10},
    sort: {
      attrs: {
        [Article.PK]: true,
        status: true,
        title: true
      },
      defaultOrder: {[Article.PK]: -1}
    }
  });
  await this.renderDataProvider(provider, 'index', {provider, searchText});
}`, `async actionView () {
  const model = await this.getModel({
    with: ['author', 'category', 'photos', 'mainPhoto', 'tags']
  });
  const comments = this.createDataProvider({
    query: model.relComments(),
    sort: {
      attrs: {
        [model.PK]: true
      },
      defaultOrder: {[model.PK]: -1}
    }
  });
  await this.renderDataProvider(comments, 'view', {model, comments});
}`, `actionCreate () {
  const model = this.spawn(Article);
  if (this.isGet()) {
    return this.renderForm('create', {model});
  }
  model.load(this.getPostParams());
  model.set('authorId', this.user.getId());
  await model.save()
    ? this.redirectToReferrer()
    : await this.renderForm('create', {model});
}`, `actionUpdate () {
  const model = await this.getModel({with: ['photos', 'tags']});
  const access = await this.user.can('updateArticle', {authorId: model.get('authorId')});
  if (!access) {
    throw new Forbidden;
  }
  return this.isPost() && await model.load(this.getPostParams()).save()
    ? this.redirectToReferrer()
    : this.renderForm('update', {model});
}`],
        'admin-file-controller': [`const Base = require('../component/CrudController');

module.exports = class FileController extends Base {

  static getConstants () {
    return {
      METHODS: {
        'upload': ['post']
      },
      actionCreate: null,
      actionUpdate: null
    };
  }  
};
module.exports.init(module);

const File = require('../model/File');`, `actionUpload () {
  const model = this.spawn(File);
  await model.upload(this.req, this.res, this.user)
    ? this.sendText(model.getId())
    : this.sendText(this.translate(model.getFirstError()), 400);
}`],
        'admin-photo-controller': [`const Base = require('../component/CrudController');

module.exports = class PhotoController extends Base {

  static getConstants () {
    return {
      METHODS: {
        'assign-main': ['post']
      }
    };
  }
};
module.exports.init(module);

const Article = require('../model/Article');
const File = require('../model/File');
const Photo = require('../model/Photo');`, `async actionCreate () {
  const model = this.spawn(Photo);
  model.scenario = 'create';
  if (this.isPost() && model.load(this.getPostParams()).save()) {
    return this.redirectToReferrer();
  }
  const articles = await Article.findToSelect().all();
  await this.render('create', {articles, model});
}`, `async actionView () {
  await super.actionView({with: ['article']});
}`, `async actionUpload () {
  const file = this.spawn(File);
  if (!await file.upload(this)) {
    return this.sendText(this.translate(file.getFirstError()), 400);
  }
  const photo = this.spawn(Photo);
  photo.set('file', file.getId());
  await photo.validate(['file'])
    ? this.sendText(file.getId())
    : this.sendText(this.translate(photo.getFirstError()), 400);
}`, `async actionAssignMain () {
  const model = await this.getModel({with: ['article']});
  const article = model.get('article');
  if (!article) {
    this.setFlash('danger', 'Article not found');
    return this.redirect(['view', model]);
  }
  article.set('mainPhotoId', model.getId());
  await article.forceSave();
  this.redirect(['article/view', article]);
}`],
    };
    const items = codes[activePathName];
    if (Array.isArray(items)) {
        $('article').find('pre.code').each((index, element) => {
            $(element).html(`<code>${escapeTags(items[index])}</code>`);
        });
    }
    hljs.initHighlightingOnLoad();
})(jQuery);

// STEP CONTROL

(function ($) {
    const $items = $('.side-menu').children();
    if ($items.length) {
        const $controls = $('<div class="step-control"></div>');
        const $active = $items.filter('.active');
        const $prev = $active.prevAll().not('.nav-header').first();
        const $next = $active.nextAll().not('.nav-header').first();
        if ($prev.length) {
            $controls.append('<button class="btn-back btn-default btn">Back</button> ');
        }
        if ($next.length) {
            $controls.append('<button class="btn-next btn-primary btn">Next</button> ');
        }
        $controls.on('click', '.btn-back', () => $prev.find('a').get(0).click());
        $controls.on('click', '.btn-next', () => $next.find('a').get(0).click());
        $('article > div > div').first().append($controls);
    }
})(jQuery);

// IMAGE VIEWER

(function($) {

    $('.image-view').each((index, element) => {
        const src = element.getAttribute('src');
        const alt = element.getAttribute('alt');
        $(element).wrap(`<a href="${src}" class="viewer-item thumb-link" title="${alt}"></a>`);
    });

    const template =
        `<div class="image-viewer modal fade" id="image-viewer" tabindex="-1" role="dialog" aria-hidden="true">
  <div class="modal-dialog modal-lg unselectable">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span
            aria-hidden="true">×</span></button>
        <h4 class="modal-title">#</h4>
      </div>
      <div class="modal-body">
        <div class="photo-viewport">
          <div class="control prev">
            <div><i class="glyphicon glyphicon-triangle-left"></i></div>
          </div>
          <div class="control next">
            <div><i class="glyphicon glyphicon-triangle-right"></i></div>
          </div>
          <div class="photo-container"><img src="" class="photo-face"></div>
        </div>
      </div>
    </div>
  </div>
</div>`;
    const $viewer = $(template);
    $(document.body).append($viewer);

    const $title = $viewer.find('.modal-title');
    const $viewport = $viewer.find('.photo-viewport');
    const $face = $viewport.find('.photo-face');
    const $prev = $viewport.find('.prev').click(()=> jumpToNext(-1));
    const $next = $viewport.find('.next').click(()=> jumpToNext(1));

    let $items = [];
    let currentIndex;

    $(document.body).on('click', 'a.viewer-item', function (event) {
        event.preventDefault();
        const $list = $(this).closest('.viewer-list');
        $items = $('a.viewer-item', $list.length ? $list : null);
        currentIndex = $items.index(this);
        if (currentIndex < 0) {
            return false;
        }
        $face.get(0).src = '';
        // hide icon of the empty image
        $face.addClass('invisible');
        loadImage();
        $viewer.modal('show');
    });

    $face.on('load', ()=> {
        $viewport.removeClass('loading');
        $face.removeClass('invisible');
        $(window).resize(); // update overlay size
    });

    function jumpToNext(step) {
        const index = currentIndex + step;
        if (index < 0 || index >= $items.length) {
            return false;
        }
        currentIndex = index;
        loadImage();
    }

    function loadImage() {
        const $item = $items.eq(currentIndex);
        $viewport.addClass('loading');
        const title = $item.attr('title');
        $title.html(title ? title : '#');
        setTimeout(function(){
            $face.get(0).src = $item.attr('href');
        }, 0);
        $prev.toggle(!!currentIndex);
        $next.toggle(currentIndex !== $items.length - 1);
    }
})(jQuery);