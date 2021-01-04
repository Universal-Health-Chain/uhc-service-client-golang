package models

var collectionNameUsers = "Users"

type User struct {
	AppId   string `bson:"appId,omitempty" json:"appId,omitempty"`
	LogoUrl string `bson:"logoUrl,omitempty" json:"logoUrl,omitempty"`

	ID       string `bson:"id,omitempty" json:"id,omitempty"`
	Username string `bson:"username,omitempty" json:"username,omitempty"`
	Password string `bson:"password,omitempty" json:"password,omitempty"`

	DidController string `bson:"did,omitempty" json:"did,omitempty"`	// 	Blockchain's DID e.g.

	Token                       string  `bson:"token,omitempty" json:"token,omitempty"`
	RefreshToken                string  `bson:"refreshToken,omitempty" json:"refreshToken,omitempty"`
	ConfirmationAccountToken    *string `bson:"confirmationAccountToken" json:"confirmationAccountToken"`
	ImplicitInvitationToken     *string `bson:"implicitInvitationToken" json:"implicitInvitationToken"`
	ConfirmationAccountAttempts int     `bson:"confirmationAccountAttempts" json:"confirmationAccountAttempts"`
	RecoverAccountToken         *string `bson:"recoverAccountToken" json:"recoverAccountToken"`
	RecoverAccountAttempts      int     `bson:"recoverAccountAttempts" json:"recoverAccountAttempts"`
	ConfirmedAccount            bool    `bson:"confirmedAccount,omitempty" json:"confirmedAccount,omitempty"`
	InvitedUser                 bool    `bson:"invitedUser,omitempty" json:"invitedUser,omitempty"`

	Email                  string                   `bson:"email,omitempty" json:"email,omitempty"`
	FirstName              string                   `bson:"firstName,omitempty" json:"firstName,omitempty"`
	LastName               string                   `bson:"lastName,omitempty" json:"lastName,omitempty"`
	PreferredLanguage      string                   `bson:"preferredLanguage,omitempty" json:"preferredLanguage,omitempty"`

	Role                   []string                 `bson:"role,omitempty" json:"role,omitempty"`
	OrganizationPermission []OrganizationPermission `bson:"organizationPermission,omitempty" json:"organizationPermission,omitempty"`
}

type UserDeletionRequest struct {
	ID            string `bson:"id,omitempty" json:"id,omitempty"`
	Username      string `bson:"username,omitempty" json:"username,omitempty"`
	DeletionToken string `bson:"deletionToken,omitempty" json:"deletionToken,omitempty"`
	Password      string `bson:"password,omitempty" json:"password,omitempty"`
	Email         string `bson:"email,omitempty" json:"email,omitempty"`
}

// Practitioner can be: administrative, driver, director, techoperator, researcher, pharmacist, doctor, nurse, paramedic, fireman, policeman ...
type OrganizationPermission struct {
	OrganizationId   string `bson:"organizationId,omitempty" json:"organizationId,omitempty"`
	OrganizationRole string `bson:"organizationRole,omitempty" json:"organizationRole,omitempty"`
	ConfirmedRole    bool   `bson:"confirmedRole" json:"confirmedRole"`
}

type UserResponse struct {
	Code    int    `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64  `bson:"count,omitempty" json:"count,omitempty"`
	Message string `bson:"message,omitempty" json:"message,omitempty"`
	Data    []User `bson:"data,omitempty" json:"data,omitempty"`
	Token   Token  `bson:"token,omitempty" json:"token,omitempty"`
}

type ConfirmUserData struct {
	Email string `bson:"email,omitempty" json:"email,omitempty"`
	Code  string `bson:"code,omitempty" json:"code,omitempty"`
}

type ChangePasswordRequest struct {
	Email       string `bson:"email,omitempty" json:"email,omitempty"`
	Code        string `bson:"code,omitempty" json:"code,omitempty"`
	NewPassword string `bson:"newPassword,omitempty" json:"newPassword,omitempty"`
}
