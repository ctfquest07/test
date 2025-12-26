const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const Challenge = require('../models/Challenge');
const User = require('../models/User');
const Submission = require('../models/Submission');
const { protect, authorize } = require('../middleware/auth');
const jwt = require('jsonwebtoken');
const { sanitizeInput, validateInput, securityHeaders } = require('../middleware/security');
const requestIp = require('request-ip');
const UAParser = require('ua-parser-js');
const crypto = require('crypto');

const Redis = require('ioredis');
// Initialize Redis for Challenge Rate Limiting
const redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Real-time logging function
const logActivity = (action, details = {}) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] CHALLENGE: ${action}`, details);
};

// Redis-based Rate limiting for flag submissions
const checkFlagSubmissionRate = async (userId, challengeId) => {
  const key = `rate:flag:${userId}:${challengeId}`;
  const maxAttempts = parseInt(process.env.FLAG_SUBMIT_MAX_ATTEMPTS) || 5;
  const windowSeconds = parseInt(process.env.FLAG_SUBMIT_WINDOW) || 60;
  const cooldownSeconds = parseInt(process.env.FLAG_SUBMIT_COOLDOWN) || 30;

  // Get attempts from Redis
  // We store attempts as a list of timestamps
  const attempts = await redisClient.lrange(key, 0, -1);
  const now = Date.now();

  // Check if user is in cooldown (blocked)
  const blockedKey = `rate:blocked:${userId}:${challengeId}`;
  const isBlocked = await redisClient.get(blockedKey);

  if (isBlocked) {
    const ttl = await redisClient.ttl(blockedKey);
    return { allowed: false, remainingTime: ttl > 0 ? ttl : cooldownSeconds };
  }

  // Filter old attempts (older than window)
  const validAttempts = attempts.filter(time => (now - parseInt(time)) < (windowSeconds * 1000));

  // If we filtered out attempts, update the list asynchronously
  if (validAttempts.length < attempts.length) {
    await redisClient.del(key);
    if (validAttempts.length > 0) {
      await redisClient.rpush(key, ...validAttempts);
      await redisClient.expire(key, windowSeconds);
    }
  }

  // Check limit
  if (validAttempts.length >= maxAttempts) {
    // Block user
    await redisClient.setex(blockedKey, cooldownSeconds, 'blocked');
    return { allowed: false, remainingTime: cooldownSeconds };
  }

  return { allowed: true };
};

// Record failed flag submission
const recordFailedSubmission = async (userId, challengeId) => {
  const key = `rate:flag:${userId}:${challengeId}`;
  const now = Date.now();
  const windowSeconds = parseInt(process.env.FLAG_SUBMIT_WINDOW) || 60;

  await redisClient.rpush(key, now);
  await redisClient.expire(key, windowSeconds);
};

// Clear attempts on successful submission
const clearSubmissionAttempts = async (userId, challengeId) => {
  const key = `rate:flag:${userId}:${challengeId}`;
  const blockedKey = `rate:blocked:${userId}:${challengeId}`;

  await redisClient.del(key);
  await redisClient.del(blockedKey);
};

// @route   GET /api/challenges
// @desc    Get all challenges with pagination (filtered by visibility for non-admin users)
// @access  Public
router.get('/', sanitizeInput, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Check if user is authenticated and get user info
    let user = null;
    if (req.headers.authorization) {
      try {
        const jwt = require('jsonwebtoken');
        const token = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        user = await User.findById(decoded.id);
      } catch (err) {
        // Token invalid, continue as non-authenticated user
      }
    }

    const query = {};
    // Show all challenges to admins, only visible challenges to others (including non-authenticated users)
    if (!user || user.role !== 'admin') {
      query.isVisible = true;
    }

    const total = await Challenge.countDocuments(query);
    const challenges = await Challenge.find(query)
      .select('-flag')
      .limit(limit)
      .skip(skip)
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      count: challenges.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      data: challenges
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// @route   GET /api/challenges/:id
// @desc    Get single challenge
// @access  Public
router.get('/:id', async (req, res) => {
  try {
    const challenge = await Challenge.findById(req.params.id).select('-flag');

    if (!challenge) {
      return res.status(404).json({
        success: false,
        message: 'Challenge not found'
      });
    }

    res.json({
      success: true,
      data: challenge
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// @route   POST /api/challenges
// @desc    Create a challenge
// @access  Private/Admin
router.post('/', protect, authorize('admin', 'superadmin'), async (req, res) => {
  try {
    const challenge = await Challenge.create(req.body);

    res.status(201).json({
      success: true,
      data: challenge
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// @route   POST /api/challenges/:id/submit
// @desc    Submit a flag for a challenge
// @access  Private
router.post('/:id/submit', protect, sanitizeInput, async (req, res) => {
  try {
    const { flag } = req.body;

    // Validate and sanitize flag input
    let submittedFlag;
    try {
      submittedFlag = validateInput.flag(flag);
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: error.message
      });
    }

    // Get challenge with flag
    const challenge = await Challenge.findById(req.params.id).select('+flag');
    if (!challenge) {
      return res.status(404).json({
        success: false,
        message: 'Challenge not found'
      });
    }

    // Get user
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.isBlocked) {
      return res.status(403).json({
        success: false,
        message: `Your account is blocked. Reason: ${user.blockedReason || 'No reason provided'}`
      });
    }

    if (!user.canSubmitFlags) {
      return res.status(403).json({
        success: false,
        message: 'You are not allowed to submit flags'
      });
    }

    if (!challenge.submissionsAllowed) {
      return res.status(403).json({
        success: false,
        message: 'Submissions for this challenge are currently blocked'
      });
    }

    // Check if already solved
    const alreadySolved = user.solvedChallenges.some(
      id => id.toString() === challenge._id.toString()
    );
    if (alreadySolved) {
      return res.status(400).json({
        success: false,
        message: 'You have already solved this challenge'
      });
    }

    // Check rate limiting for flag submissions
    const rateCheck = await checkFlagSubmissionRate(req.user._id, challenge._id);
    if (!rateCheck.allowed) {
      return res.status(429).json({
        success: false,
        message: `Too many attempts. Please wait ${rateCheck.remainingTime} seconds before trying again.`,
        remainingTime: rateCheck.remainingTime
      });
    }

    // Get IP and User Agent for tracking
    const clientIp = requestIp.getClientIp(req);
    const userAgent = req.get('User-Agent') || 'Unknown';

    // Check flag using constant-time comparison to prevent timing attacks
    const expectedFlag = challenge.flag.trim();
    const submittedBuffer = Buffer.from(submittedFlag, 'utf8');
    const expectedBuffer = Buffer.from(expectedFlag, 'utf8');

    // Ensure buffers are same length to prevent timing attacks
    const maxLength = Math.max(submittedBuffer.length, expectedBuffer.length);
    const paddedSubmitted = Buffer.alloc(maxLength);
    const paddedExpected = Buffer.alloc(maxLength);

    submittedBuffer.copy(paddedSubmitted);
    expectedBuffer.copy(paddedExpected);

    const isCorrect = crypto.timingSafeEqual(paddedSubmitted, paddedExpected) &&
      submittedFlag.length === expectedFlag.length;

    // Create submission record (both success and failure)
    await Submission.create({
      user: req.user._id,
      challenge: challenge._id,
      submittedFlag: submittedFlag,
      isCorrect: isCorrect,
      points: isCorrect ? challenge.points : 0,
      ipAddress: clientIp,
      userAgent: userAgent
    });

    if (!isCorrect) {
      // Record failed submission for rate limiting
      await recordFailedSubmission(req.user._id, challenge._id);

      return res.status(400).json({
        success: false,
        message: 'Incorrect flag'
      });
    }

    // Clear rate limiting attempts on successful submission
    await clearSubmissionAttempts(req.user._id, challenge._id);

    // Use transaction for atomic operations to prevent race conditions
    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        // Update user with solve time
        await User.findByIdAndUpdate(
          req.user._id,
          {
            $addToSet: { solvedChallenges: challenge._id },
            $inc: { points: challenge.points },
            $set: { lastSolveTime: new Date() }
          },
          { session }
        );

        // Update challenge
        await Challenge.findByIdAndUpdate(
          req.params.id,
          { $addToSet: { solvedBy: req.user._id } },
          { session }
        );
      });
    } finally {
      await session.endSession();
    }

    logActivity('FLAG_SUBMITTED_SUCCESS', {
      userId: req.user._id,
      challengeId: challenge._id,
      challengeTitle: challenge.title,
      points: challenge.points
    });

    res.json({
      success: true,
      message: `Challenge "${challenge.title}" solved successfully!`,
      points: challenge.points,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Challenge submission error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   DELETE /api/challenges/:id
// @desc    Delete a challenge
// @access  Private/Admin
router.delete('/:id', protect, authorize('admin', 'superadmin'), async (req, res) => {
  try {
    const challenge = await Challenge.findById(req.params.id);

    if (!challenge) {
      return res.status(404).json({
        success: false,
        message: 'Challenge not found'
      });
    }

    await challenge.deleteOne();

    res.json({
      success: true,
      message: 'Challenge deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// @route   PUT /api/challenges/:id
// @desc    Update a challenge
// @access  Private/Admin
router.put('/:id', protect, authorize('admin', 'superadmin'), async (req, res) => {
  try {
    console.log('Update challenge request:', {
      id: req.params.id,
      body: req.body
    });

    const challenge = await Challenge.findById(req.params.id);

    if (!challenge) {
      return res.status(404).json({
        success: false,
        message: 'Challenge not found'
      });
    }

    // If isVisible is being updated, log the change
    if (req.body.hasOwnProperty('isVisible')) {
      console.log('Updating visibility:', {
        challengeId: challenge._id,
        oldVisibility: challenge.isVisible,
        newVisibility: req.body.isVisible
      });
    }

    const updatedChallenge = await Challenge.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true
      }
    );

    console.log('Challenge updated successfully:', {
      challengeId: updatedChallenge._id,
      isVisible: updatedChallenge.isVisible
    });

    res.json({
      success: true,
      data: updatedChallenge
    });
  } catch (error) {
    console.error('Error updating challenge:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

module.exports = router;
