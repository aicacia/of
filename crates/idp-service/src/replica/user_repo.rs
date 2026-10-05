use std::sync::Arc;

use chrono::{DateTime, Timelike, Utc};
use db::{
    Engine, FromRow, FromRowError, Kernel, Query, QueryColumn, QueryDelete, QueryExpr,
    QueryExprValue, QueryFrom, QueryInsert, QuerySelect, QueryUpdate, QueryUpdateAssignment, Row,
    RowCodec, Statement, Uuid, Value,
};
use idp_model::{
    contract::Sex,
    model::{Id, User, UserEmail, UserPassword, UserPhoneNumber},
    replica::allows_authentication,
};

use crate::{
    PasswordConfig, encrypt_password,
    repo::{RepoError, RepoResult, UserRepo},
};

const USERS: &str = "users";
const EMAILS: &str = "user_emails";
const PHONES: &str = "user_phone_numbers";
const CREDENTIALS: &str = "credentials";
const PASSWORD_KIND: &str = "password";

macro_rules! decode {
    ($row:expr, $columns:expr, $column:expr) => {
        db::decode(db::value($row, $columns, $column)?, $column)
    };
    ($type:ty, $row:expr, $columns:expr, $column:expr) => {
        db::decode::<$type>(db::value($row, $columns, $column)?, $column)
    };
}

const USER_COLUMNS: [&str; 16] = [
    "id",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "sex",
    "birthdate",
    "zoneinfo",
    "locale",
    "created_at",
    "updated_at",
    "handle",
];
const EMAIL_COLUMNS: [&str; 7] = [
    "id",
    "user_id",
    "email",
    "verified",
    "primary_email",
    "created_at",
    "updated_at",
];
const PHONE_COLUMNS: [&str; 7] = [
    "id",
    "user_id",
    "phone_number",
    "verified",
    "primary_phone",
    "created_at",
    "updated_at",
];
const CREDENTIAL_COLUMNS: [&str; 8] = [
    "id",
    "user_id",
    "kind",
    "secret_hash",
    "active",
    "revoked_at",
    "created_at",
    "updated_at",
];

pub struct DbUserRepo<K, R>
where
    K: Kernel + Send + Sync,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    engine: Arc<Engine<K, R>>,
    password_config: PasswordConfig,
}

impl<K, R> DbUserRepo<K, R>
where
    K: Kernel + Send + Sync,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    #[must_use]
    pub const fn new(engine: Arc<Engine<K, R>>, password_config: PasswordConfig) -> Self {
        Self {
            engine,
            password_config,
        }
    }

    async fn rows<T: FromRow>(&self, query: Query, missing: &str) -> RepoResult<Vec<T>> {
        let mut results = self
            .engine
            .execute(vec![Statement::Query(query)])
            .await
            .map_err(db_error)?;
        results
            .pop()
            .ok_or_else(|| RepoError::InvalidInput(missing.into()))?
            .rows_as::<T>()
            .map_err(row_error)
    }

    async fn users(&self, predicate: Option<QueryExpr>) -> RepoResult<Vec<User>> {
        self.rows::<UserRow>(
            select(USERS, &USER_COLUMNS, predicate),
            "missing user query result",
        )
        .await?
        .into_iter()
        .map(User::try_from)
        .collect()
    }

    async fn emails(&self, user_id: Id) -> RepoResult<Vec<UserEmail>> {
        self.rows::<EmailRow>(
            select(
                EMAILS,
                &EMAIL_COLUMNS,
                Some(equals(EMAILS, "user_id", Value::Uuid(user_id))),
            ),
            "missing email query result",
        )
        .await?
        .into_iter()
        .map(UserEmail::try_from)
        .collect()
    }

    async fn phones(&self, user_id: Id) -> RepoResult<Vec<UserPhoneNumber>> {
        self.rows::<PhoneRow>(
            select(
                PHONES,
                &PHONE_COLUMNS,
                Some(equals(PHONES, "user_id", Value::Uuid(user_id))),
            ),
            "missing phone query result",
        )
        .await?
        .into_iter()
        .map(UserPhoneNumber::try_from)
        .collect()
    }

    async fn credentials(&self, user_id: Id) -> RepoResult<Vec<CredentialRow>> {
        self.rows(
            select(
                CREDENTIALS,
                &CREDENTIAL_COLUMNS,
                Some(and(
                    equals(CREDENTIALS, "user_id", Value::Uuid(user_id)),
                    equals(CREDENTIALS, "kind", Value::Text(PASSWORD_KIND.into())),
                )),
            ),
            "missing credential query result",
        )
        .await
    }

    async fn ensure_credential_clear(&self, id: Id) -> RepoResult<()> {
        if allows_authentication(&self.engine, &[id], &[])
            .await
            .map_err(db_error)?
        {
            Ok(())
        } else {
            Err(RepoError::InvalidInput("conflicted credential".into()))
        }
    }
}

impl<K, R> UserRepo for DbUserRepo<K, R>
where
    K: Kernel + Send + Sync,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    async fn find_user_by_id(&self, id: Id) -> RepoResult<Option<User>> {
        Ok(self
            .users(Some(equals(USERS, "id", Value::Uuid(id))))
            .await?
            .into_iter()
            .next())
    }

    async fn list_users(&self, offset: u32, limit: u32) -> RepoResult<Vec<User>> {
        let mut users = self.users(None).await?;
        users.sort_by_key(|user| core::cmp::Reverse(user.created_at));
        Ok(users
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn find_user_by_username_or_email(&self, identifier: &str) -> RepoResult<Option<User>> {
        let user = self
            .users(Some(equals(
                USERS,
                "handle",
                Value::Text(identifier.into()),
            )))
            .await?
            .into_iter()
            .next();
        if user.is_some() {
            return Ok(user);
        }
        let email = self
            .rows::<EmailRow>(
                select(
                    EMAILS,
                    &EMAIL_COLUMNS,
                    Some(equals(EMAILS, "email", Value::Text(identifier.into()))),
                ),
                "missing email query result",
            )
            .await?
            .into_iter()
            .map(UserEmail::try_from)
            .collect::<RepoResult<Vec<_>>>()?
            .into_iter()
            .max_by_key(|email| (email.primary, core::cmp::Reverse(email.id)));
        match email {
            Some(email) => self.find_user_by_id(email.user_id).await,
            None => Ok(None),
        }
    }

    async fn find_user_emails_by_user_id(&self, user_id: Id) -> RepoResult<Vec<UserEmail>> {
        let mut emails = self.emails(user_id).await?;
        emails.sort_by_key(|email| (core::cmp::Reverse(email.primary), email.id));
        Ok(emails)
    }

    async fn find_user_phone_numbers_by_user_id(
        &self,
        user_id: Id,
    ) -> RepoResult<Vec<UserPhoneNumber>> {
        let mut phones = self.phones(user_id).await?;
        phones.sort_by_key(|phone| (core::cmp::Reverse(phone.primary), phone.id));
        Ok(phones)
    }

    async fn find_user_password_by_user_id(&self, user_id: Id) -> RepoResult<Option<UserPassword>> {
        let credential = self
            .credentials(user_id)
            .await?
            .into_iter()
            .find(|credential| credential.active && credential.revoked_at.is_none());
        if let Some(credential) = credential.as_ref() {
            self.ensure_credential_clear(credential.id).await?;
        }
        credential.map(UserPassword::try_from).transpose()
    }

    async fn create_user_with_password(&self, name: &str, password: &str) -> RepoResult<User> {
        self.create_user_with_password_and_ids(Id::now_v7(), Id::now_v7(), name, password)
            .await
    }

    async fn create_user_with_password_and_ids(
        &self,
        user_id: Id,
        credential_id: Id,
        name: &str,
        password: &str,
    ) -> RepoResult<User> {
        if password.trim().is_empty() {
            return Err(RepoError::InvalidInput("password is required".into()));
        }
        let now = now();
        let user = User {
            id: user_id,
            name: name.into(),
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            profile: None,
            picture: None,
            website: None,
            sex: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            created_at: now,
            updated_at: now,
        };
        let credential = CredentialRow {
            id: credential_id,
            user_id: user.id,
            kind: PASSWORD_KIND.into(),
            secret_hash: encrypt_password(&self.password_config, password)
                .map_err(|error| RepoError::Other(error.into()))?,
            active: true,
            revoked_at: None,
            created_at: now.timestamp(),
            updated_at: now.timestamp(),
        };
        self.engine
            .execute(vec![
                Statement::Query(Query::Insert(QueryInsert {
                    table: USERS.into(),
                    row: UserRow::from(&user).into(),
                    returning: None,
                })),
                Statement::Query(Query::Insert(QueryInsert {
                    table: CREDENTIALS.into(),
                    row: credential.into(),
                    returning: None,
                })),
            ])
            .await
            .map_err(db_error)?;
        Ok(user)
    }

    async fn update_user(&self, user: User) -> RepoResult<User> {
        if self.find_user_by_id(user.id).await?.is_none() {
            return Err(RepoError::InvalidInput("user not found".into()));
        }
        let updated_at = now();
        self.engine
            .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                from: from(USERS),
                assignments: UserRow::assignments(&user, updated_at),
                predicate: Some(equals(USERS, "id", Value::Uuid(user.id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(User { updated_at, ..user })
    }

    async fn upsert_primary_user_email(
        &self,
        user_id: Id,
        email: &str,
        verified: bool,
    ) -> RepoResult<()> {
        let now = now().timestamp();
        let mut emails = self.emails(user_id).await?;
        let email_row = emails.iter_mut().find(|existing| existing.email == email);
        if let Some(existing) = email_row {
            self.engine
                .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                    from: from(EMAILS),
                    assignments: vec![
                        assignment(EMAILS, "verified", bool_value(verified)),
                        assignment(EMAILS, "primary_email", bool_value(true)),
                        assignment(EMAILS, "updated_at", Value::Integer(now)),
                    ],
                    predicate: Some(equals(EMAILS, "id", Value::Uuid(existing.id))),
                    returning: None,
                }))])
                .await
                .map_err(db_error)?;
        } else {
            let row = EmailRow {
                id: Id::now_v7(),
                user_id,
                email: email.into(),
                verified: i64::from(verified),
                primary: 1,
                created_at: now,
                updated_at: now,
            };
            self.engine
                .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                    table: EMAILS.into(),
                    row: row.into(),
                    returning: None,
                }))])
                .await
                .map_err(db_error)?;
        }
        for existing in emails
            .into_iter()
            .filter(|existing| existing.email != email)
        {
            self.engine
                .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                    from: from(EMAILS),
                    assignments: vec![
                        assignment(EMAILS, "primary_email", bool_value(false)),
                        assignment(EMAILS, "updated_at", Value::Integer(now)),
                    ],
                    predicate: Some(equals(EMAILS, "id", Value::Uuid(existing.id))),
                    returning: None,
                }))])
                .await
                .map_err(db_error)?;
        }
        Ok(())
    }

    async fn upsert_primary_user_phone_number(
        &self,
        user_id: Id,
        phone_number: &str,
        verified: bool,
    ) -> RepoResult<()> {
        let now = now().timestamp();
        let phones = self.phones(user_id).await?;
        if let Some(existing) = phones
            .iter()
            .find(|existing| existing.phone_number == phone_number)
        {
            self.engine
                .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                    from: from(PHONES),
                    assignments: vec![
                        assignment(PHONES, "verified", bool_value(verified)),
                        assignment(PHONES, "primary_phone", bool_value(true)),
                        assignment(PHONES, "updated_at", Value::Integer(now)),
                    ],
                    predicate: Some(equals(PHONES, "id", Value::Uuid(existing.id))),
                    returning: None,
                }))])
                .await
                .map_err(db_error)?;
        } else {
            let row = PhoneRow {
                id: Id::now_v7(),
                user_id,
                phone_number: phone_number.into(),
                verified,
                primary: true,
                created_at: now,
                updated_at: now,
            };
            self.engine
                .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                    table: PHONES.into(),
                    row: row.into(),
                    returning: None,
                }))])
                .await
                .map_err(db_error)?;
        }
        for existing in phones
            .into_iter()
            .filter(|existing| existing.phone_number != phone_number)
        {
            self.engine
                .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                    from: from(PHONES),
                    assignments: vec![
                        assignment(PHONES, "primary_phone", bool_value(false)),
                        assignment(PHONES, "updated_at", Value::Integer(now)),
                    ],
                    predicate: Some(equals(PHONES, "id", Value::Uuid(existing.id))),
                    returning: None,
                }))])
                .await
                .map_err(db_error)?;
        }
        Ok(())
    }

    async fn replace_user_password(&self, user_id: Id, password: &str) -> RepoResult<()> {
        let password_hash = encrypt_password(&self.password_config, password)
            .map_err(|error| RepoError::Other(error.into()))?;
        let now = now().timestamp();
        for credential in self.credentials(user_id).await? {
            if credential.active {
                self.ensure_credential_clear(credential.id).await?;
            }
        }
        for credential in self.credentials(user_id).await? {
            self.engine
                .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                    from: from(CREDENTIALS),
                    assignments: vec![
                        assignment(CREDENTIALS, "active", bool_value(false)),
                        assignment(CREDENTIALS, "updated_at", Value::Integer(now)),
                    ],
                    predicate: Some(equals(CREDENTIALS, "id", Value::Uuid(credential.id))),
                    returning: None,
                }))])
                .await
                .map_err(db_error)?;
        }
        self.engine
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: CREDENTIALS.into(),
                row: CredentialRow {
                    id: Id::now_v7(),
                    user_id,
                    kind: PASSWORD_KIND.into(),
                    secret_hash: password_hash,
                    active: true,
                    revoked_at: None,
                    created_at: now,
                    updated_at: now,
                }
                .into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn delete_user_by_id(&self, user_id: Id) -> RepoResult<()> {
        self.engine
            .execute(vec![Statement::Query(Query::Delete(QueryDelete {
                from: from(USERS),
                predicate: Some(equals(USERS, "id", Value::Uuid(user_id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

#[derive(Debug)]
struct UserRow {
    id: Uuid,
    name: String,
    given_name: Option<String>,
    family_name: Option<String>,
    middle_name: Option<String>,
    nickname: Option<String>,
    profile: Option<String>,
    picture: Option<String>,
    website: Option<String>,
    sex: Option<i64>,
    birthdate: Option<String>,
    zoneinfo: Option<String>,
    locale: Option<String>,
    created_at: i64,
    updated_at: i64,
    handle: String,
}
impl FromRow for UserRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: decode!(row, columns, "id")?,
            name: decode!(row, columns, "name")?,
            given_name: decode!(row, columns, "given_name")?,
            family_name: decode!(row, columns, "family_name")?,
            middle_name: decode!(row, columns, "middle_name")?,
            nickname: decode!(row, columns, "nickname")?,
            profile: decode!(row, columns, "profile")?,
            picture: decode!(row, columns, "picture")?,
            website: decode!(row, columns, "website")?,
            sex: decode!(row, columns, "sex")?,
            birthdate: decode!(row, columns, "birthdate")?,
            zoneinfo: decode!(row, columns, "zoneinfo")?,
            locale: decode!(row, columns, "locale")?,
            created_at: decode!(row, columns, "created_at")?,
            updated_at: decode!(row, columns, "updated_at")?,
            handle: decode!(row, columns, "handle")?,
        })
    }
}
impl TryFrom<UserRow> for User {
    type Error = RepoError;
    fn try_from(row: UserRow) -> RepoResult<Self> {
        Ok(Self {
            id: row.id,
            name: row.name,
            given_name: row.given_name,
            family_name: row.family_name,
            middle_name: row.middle_name,
            nickname: row.nickname,
            profile: row.profile,
            picture: row.picture,
            website: row.website,
            sex: row.sex.map(sex).transpose()?,
            birthdate: row.birthdate.map(birthdate).transpose()?,
            zoneinfo: row.zoneinfo,
            locale: row.locale,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
        })
    }
}
impl From<&User> for UserRow {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            name: user.name.clone(),
            given_name: user.given_name.clone(),
            family_name: user.family_name.clone(),
            middle_name: user.middle_name.clone(),
            nickname: user.nickname.clone(),
            profile: user.profile.clone(),
            picture: user.picture.clone(),
            website: user.website.clone(),
            sex: user.sex.map(|value| value as i64),
            birthdate: user.birthdate.map(|value| value.to_rfc3339()),
            zoneinfo: user.zoneinfo.clone(),
            locale: user.locale.clone(),
            created_at: user.created_at.timestamp(),
            updated_at: user.updated_at.timestamp(),
            handle: user.name.clone(),
        }
    }
}
impl UserRow {
    fn assignments(user: &User, updated_at: DateTime<Utc>) -> Vec<QueryUpdateAssignment> {
        let row = Self::from(user);
        vec![
            assignment(USERS, "name", Value::Text(row.name)),
            assignment(USERS, "given_name", option_text(row.given_name)),
            assignment(USERS, "family_name", option_text(row.family_name)),
            assignment(USERS, "middle_name", option_text(row.middle_name)),
            assignment(USERS, "nickname", option_text(row.nickname)),
            assignment(USERS, "profile", option_text(row.profile)),
            assignment(USERS, "picture", option_text(row.picture)),
            assignment(USERS, "website", option_text(row.website)),
            assignment(USERS, "sex", row.sex.map_or(Value::Null, Value::Integer)),
            assignment(USERS, "birthdate", option_text(row.birthdate)),
            assignment(USERS, "zoneinfo", option_text(row.zoneinfo)),
            assignment(USERS, "locale", option_text(row.locale)),
            assignment(USERS, "updated_at", Value::Integer(updated_at.timestamp())),
        ]
    }
}
impl From<UserRow> for Row {
    fn from(row: UserRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Text(row.handle),
            Value::Text(row.name),
            option_text(row.given_name),
            option_text(row.family_name),
            option_text(row.middle_name),
            option_text(row.nickname),
            option_text(row.profile),
            option_text(row.picture),
            option_text(row.website),
            row.sex.map_or(Value::Null, Value::Integer),
            option_text(row.birthdate),
            option_text(row.zoneinfo),
            option_text(row.locale),
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

#[derive(Debug)]
struct EmailRow {
    id: Uuid,
    user_id: Uuid,
    email: String,
    verified: i64,
    primary: i64,
    created_at: i64,
    updated_at: i64,
}
impl FromRow for EmailRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: decode!(row, columns, "id")?,
            user_id: decode!(row, columns, "user_id")?,
            email: decode!(row, columns, "email")?,
            verified: decode!(row, columns, "verified")?,
            primary: decode!(row, columns, "primary_email")?,
            created_at: decode!(row, columns, "created_at")?,
            updated_at: decode!(row, columns, "updated_at")?,
        })
    }
}
impl TryFrom<EmailRow> for UserEmail {
    type Error = RepoError;
    fn try_from(row: EmailRow) -> RepoResult<Self> {
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            email: row.email,
            verified: row.verified != 0,
            primary: row.primary != 0,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
        })
    }
}
impl From<EmailRow> for Row {
    fn from(row: EmailRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Uuid(row.user_id),
            Value::Text(row.email),
            Value::Integer(row.verified),
            Value::Integer(row.primary),
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

#[derive(Debug)]
struct PhoneRow {
    id: Uuid,
    user_id: Uuid,
    phone_number: String,
    verified: bool,
    primary: bool,
    created_at: i64,
    updated_at: i64,
}
impl FromRow for PhoneRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: decode!(row, columns, "id")?,
            user_id: decode!(row, columns, "user_id")?,
            phone_number: decode!(row, columns, "phone_number")?,
            verified: decode!(i64, row, columns, "verified")? != 0,
            primary: decode!(i64, row, columns, "primary_phone")? != 0,
            created_at: decode!(row, columns, "created_at")?,
            updated_at: decode!(row, columns, "updated_at")?,
        })
    }
}
impl TryFrom<PhoneRow> for UserPhoneNumber {
    type Error = RepoError;
    fn try_from(row: PhoneRow) -> RepoResult<Self> {
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            phone_number: row.phone_number,
            verified: row.verified,
            primary: row.primary,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
        })
    }
}
impl From<PhoneRow> for Row {
    fn from(row: PhoneRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Uuid(row.user_id),
            Value::Text(row.phone_number),
            bool_value(row.verified),
            bool_value(row.primary),
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

#[derive(Debug)]
struct CredentialRow {
    id: Uuid,
    user_id: Uuid,
    kind: String,
    secret_hash: String,
    active: bool,
    revoked_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}
impl FromRow for CredentialRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: decode!(row, columns, "id")?,
            user_id: decode!(row, columns, "user_id")?,
            kind: decode!(row, columns, "kind")?,
            secret_hash: decode!(row, columns, "secret_hash")?,
            active: decode!(i64, row, columns, "active")? != 0,
            revoked_at: decode!(row, columns, "revoked_at")?,
            created_at: decode!(row, columns, "created_at")?,
            updated_at: decode!(row, columns, "updated_at")?,
        })
    }
}
impl TryFrom<CredentialRow> for UserPassword {
    type Error = RepoError;
    fn try_from(row: CredentialRow) -> RepoResult<Self> {
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            active: row.active,
            password_hash: row.secret_hash,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
        })
    }
}
impl From<CredentialRow> for Row {
    fn from(row: CredentialRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Uuid(row.user_id),
            Value::Text(row.kind),
            Value::Text(row.secret_hash),
            bool_value(row.active),
            row.revoked_at.map_or(Value::Null, Value::Integer),
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

fn now() -> DateTime<Utc> {
    Utc::now()
        .with_nanosecond(0)
        .expect("zero nanoseconds is valid")
}
fn timestamp(value: i64) -> RepoResult<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| RepoError::InvalidInput("invalid user timestamp".into()))
}
fn birthdate(value: String) -> RepoResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| RepoError::InvalidInput("invalid user birthdate".into()))
}
fn sex(value: i64) -> RepoResult<Sex> {
    match value {
        0 => Ok(Sex::Male),
        1 => Ok(Sex::Female),
        _ => Err(RepoError::InvalidInput("invalid user sex".into())),
    }
}
fn db_error(error: db::EngineError) -> RepoError {
    RepoError::InvalidInput(error.to_string())
}
fn row_error(error: FromRowError) -> RepoError {
    RepoError::InvalidInput(error.to_string())
}
fn option_text(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::Text)
}
fn bool_value(value: bool) -> Value {
    Value::Integer(i64::from(value))
}
fn from(table: &str) -> QueryFrom {
    QueryFrom {
        table: table.into(),
        joins: vec![],
    }
}
fn column(table: &str, column: &str) -> QueryColumn {
    QueryColumn::new(table.into(), column.into())
}
fn expr_value(value: Value) -> QueryExpr {
    QueryExpr::Value(QueryExprValue::Value(value))
}
fn equals(table: &str, column_name: &str, value: Value) -> QueryExpr {
    QueryExpr::Equals(
        Box::new(QueryExpr::Value(QueryExprValue::Column(column(
            table,
            column_name,
        )))),
        Box::new(expr_value(value)),
    )
}

fn and(left: QueryExpr, right: QueryExpr) -> QueryExpr {
    QueryExpr::And(Box::new(left), Box::new(right))
}
fn assignment(table: &str, column_name: &str, value: Value) -> QueryUpdateAssignment {
    QueryUpdateAssignment {
        column: column(table, column_name),
        value: QueryExprValue::Value(value),
    }
}
fn select(table: &str, columns: &[&str], predicate: Option<QueryExpr>) -> Query {
    Query::Select(QuerySelect {
        from: from(table),
        projection: columns
            .iter()
            .map(|column_name| column(table, column_name))
            .collect(),
        distinct: false,
        predicate,
        aggregates: vec![],
        text_concats: vec![],
        group_by: vec![],
        order_by: vec![],
        limit: None,
        offset: None,
        having: None,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use db::{AutomergeRowCodec, Engine, InMemoryKernel};
    use idp_model::replica::up;

    use super::*;

    #[tokio::test]
    async fn manages_uuid_users_and_password_credentials() {
        let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
        up(&engine).await.unwrap();
        let repo = DbUserRepo::new(engine, PasswordConfig::default());
        let user = repo
            .create_user_with_password("alice", "password")
            .await
            .unwrap();

        assert_eq!(
            repo.find_user_by_username_or_email("alice").await.unwrap(),
            Some(user.clone())
        );
        assert!(
            repo.find_user_password_by_user_id(user.id)
                .await
                .unwrap()
                .is_some()
        );
        repo.upsert_primary_user_email(user.id, "alice@example.test", true)
            .await
            .unwrap();
        repo.upsert_primary_user_phone_number(user.id, "+15555550100", true)
            .await
            .unwrap();
        assert_eq!(
            repo.find_user_by_username_or_email("alice@example.test")
                .await
                .unwrap(),
            Some(user.clone())
        );
        assert_eq!(
            repo.find_user_emails_by_user_id(user.id)
                .await
                .unwrap()
                .len(),
            1
        );
        repo.replace_user_password(user.id, "new-password")
            .await
            .unwrap();
        assert!(
            repo.find_user_password_by_user_id(user.id)
                .await
                .unwrap()
                .is_some()
        );
    }
}
