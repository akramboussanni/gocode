package config

const LockoutCount = 5
const LockoutDuration = 3600         //in seconds
const FailedLoginBacktrack = 1800    //in seconds
const ForgotPasswordExpiry = 3600    //in seconds
const EmailConfirmExpiry = 3600 * 24 //in seconds
const RecaptchaThreshold float32 = 0.5
