# 🚀 Deployment Checklist for Render

## Pre-Deployment Checklist

### ✅ Code Preparation
- [ ] All files are committed to Git
- [ ] `requirements.txt` contains all dependencies
- [ ] `render.yaml` is configured correctly
- [ ] `runtime.txt` specifies Python version
- [ ] `app.py` uses `os.environ.get('PORT', 5000)` for port
- [ ] All templates are in `templates/` directory
- [ ] All static files are in `static/` directory

### ✅ GitHub Repository
- [ ] Repository is public or Render has access
- [ ] Code is pushed to main/master branch
- [ ] No sensitive data in repository (use environment variables)

### ✅ Render Account
- [ ] Render account created
- [ ] GitHub account connected to Render
- [ ] Free tier plan available

## Deployment Steps

### 1. Initial Setup
- [ ] Go to [Render Dashboard](https://dashboard.render.com/)
- [ ] Click "New +" → "Blueprint"
- [ ] Connect your GitHub repository
- [ ] Render will auto-detect `render.yaml`

### 2. Environment Variables (Optional)
Set these in Render dashboard after deployment:

**Required (Auto-generated):**
- [ ] `SECRET_KEY` - Flask secret key
- [ ] `JWT_SECRET_KEY` - JWT signing key  
- [ ] `ENCRYPTION_KEY` - File encryption key

**Email Setup (Optional):**
- [ ] `MAIL_SERVER` = `smtp.gmail.com`
- [ ] `MAIL_PORT` = `587`
- [ ] `MAIL_USE_TLS` = `true`
- [ ] `MAIL_USERNAME` = Your Gmail address
- [ ] `MAIL_PASSWORD` = Gmail app password
- [ ] `MAIL_DEFAULT_SENDER` = Your Gmail address

### 3. Gmail App Password Setup (Optional)
- [ ] Enable 2-factor authentication on Gmail
- [ ] Go to Google Account → Security → 2-Step Verification
- [ ] Generate App Password for "Mail"
- [ ] Use this password in `MAIL_PASSWORD` environment variable

### 4. Deployment Verification
- [ ] Build completes successfully
- [ ] Application starts without errors
- [ ] Can access the deployed URL
- [ ] Admin login works: `admin@political.com` / `admin123`
- [ ] All pages load correctly
- [ ] File uploads work (if needed)

## Post-Deployment

### ✅ Testing
- [ ] Test admin login
- [ ] Test user registration
- [ ] Test event creation
- [ ] Test QR code generation
- [ ] Test email notifications (if configured)
- [ ] Test file uploads
- [ ] Test all major features

### ✅ Monitoring
- [ ] Check Render logs for errors
- [ ] Monitor application performance
- [ ] Set up alerts if needed
- [ ] Check disk usage (free tier has limits)

## Troubleshooting

### Common Issues
- [ ] Build fails → Check `requirements.txt`
- [ ] Runtime errors → Check Render logs
- [ ] Email not working → Verify Gmail app password
- [ ] File upload issues → Check directory permissions
- [ ] 500 errors → Check application logs

### Useful Commands
```bash
# Check deployment status
curl https://your-app-name.onrender.com

# Check logs in Render dashboard
# Go to your service → Logs

# Test locally before deploying
python app.py
```

## Security Notes

### ✅ Security Checklist
- [ ] No hardcoded secrets in code
- [ ] Environment variables used for sensitive data
- [ ] HTTPS enabled (automatic on Render)
- [ ] Input validation working
- [ ] Rate limiting active
- [ ] File upload restrictions in place

### ✅ Data Backup
- [ ] Data files are in `data/` directory
- [ ] Consider backing up data files
- [ ] Monitor disk usage (free tier limits)

## Performance Optimization

### ✅ Optimization Checklist
- [ ] Static files are properly served
- [ ] Images are optimized
- [ ] Database queries are efficient
- [ ] Caching implemented where needed
- [ ] Rate limiting configured appropriately

## Support Resources

- [Render Documentation](https://render.com/docs)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Render Community](https://community.render.com/)

---

**🎉 Deployment Complete!**

Your Political Event Management System is now live at:
`https://your-app-name.onrender.com`

**Default Admin Credentials:**
- Email: `admin@political.com`
- Password: `admin123`
