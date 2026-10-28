/**
 * Sample datasets for interactive ScamLens demonstrations.
 * In accordance with requirements: Loading a sample must NEVER automatically
 * analyse it. Visitors must click the analysis button themselves.
 */

import { MessageSample, UrlSample } from '../types/analyzer';

export const MESSAGE_SAMPLES: MessageSample[] = [
  {
    id: 'sample_internship',
    title: 'Fake Internship Registration Fee',
    type: 'Internship Scam',
    badgeColor: 'text-amber-400 bg-amber-950/40 border-amber-800/40',
    description: 'Guaranteed tech internship promising ₹45,000/mo but demanding an upfront refundable kit fee.',
    text: `Congratulations! You have been shortlisted for the 2-Month Google Summer Remote Internship (Stipend: ₹45,000/month). To confirm your seat and dispatch the developer onboarding laptop kit, kindly pay the mandatory registration and verification deposit of ₹1,499 at http://internship-portal-verify.xyz/pay before 6 PM today. Deposit is 100% refundable upon joining. Hurry, only 3 seats left!`,
  },
  {
    id: 'sample_kyc',
    title: 'Suspicious Bank KYC Verification',
    type: 'Bank KYC Phishing',
    badgeColor: 'text-red-400 bg-red-950/40 border-red-800/40',
    description: 'Threatens immediate bank account deactivation with a fraudulent verification link.',
    text: `Dear Customer, your HDFC Bank account access has been restricted due to overdue PAN-Aadhaar KYC verification. Your netbanking and debit card services will be permanently suspended within 24 hours. Click http://hdfc-bank-kyc-update.com/login to verify your credentials, PAN, and submit your OTP immediately.`,
  },
  {
    id: 'sample_upi_refund',
    title: 'Suspicious UPI Refund Request',
    type: 'UPI Refund Trap',
    badgeColor: 'text-rose-400 bg-rose-950/40 border-rose-800/40',
    description: 'Claims excess money was mistakenly sent and requests a UPI PIN to process a "refund".',
    text: `Dear customer, our accounts team accidentally sent ₹3,500 extra to your Google Pay number for your recent order refund. We have initiated a reverse UPI collect request. Please open PhonePe or Google Pay, approve the collect request, and enter your UPI PIN to process your ₹3,500 refund back to your balance.`,
  },
  {
    id: 'sample_college',
    title: 'Ordinary College Meeting Message',
    type: 'Legitimate College Notice',
    badgeColor: 'text-emerald-400 bg-emerald-950/40 border-emerald-800/40',
    description: 'Authentic student club announcement with zero financial or credential requests.',
    text: `Hi team! Reminder that our College Robotics Club weekly sprint meeting will take place tomorrow at 4:30 PM in Room 302, Academic Block C. Please review the sensor testing notes and bring your team project logs. See you there!`,
  },
  {
    id: 'sample_electricity',
    title: 'Electricity Disconnection Panic',
    type: 'Utility Cutoff Scam',
    badgeColor: 'text-amber-400 bg-amber-950/40 border-amber-800/40',
    description: 'Threatens immediate power disconnection tonight due to unpaid bill.',
    text: `Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from the electricity office because your previous month bill was not updated. Please immediately contact our power officer at 9876543210.`,
  },
  {
    id: 'sample_courier',
    title: 'Courier Redelivery Fee Trap',
    type: 'Courier Delivery Trap',
    badgeColor: 'text-orange-400 bg-orange-950/40 border-orange-800/40',
    description: 'Falsely claims package cannot be delivered due to incomplete address and demands redelivery fee.',
    text: `India Post: Your package cannot be delivered due to incomplete address. Please update delivery address and pay Rs 25 redelivery fee at http://post-delivery-update.xyz/pay within 24 hours.`,
  },
];

export const URL_SAMPLES: UrlSample[] = [
  {
    id: 'url_spoofed_bank',
    label: 'Spoofed Bank on Suspicious TLD (.xyz)',
    url: 'http://hdfc-bank-kyc-update.xyz/login.php?verify=token92',
    category: 'Bank Phishing / Insecure HTTP / Abused TLD',
  },
  {
    id: 'url_raw_ip',
    label: 'Raw Numeric IP Address Host',
    url: 'http://185.193.125.77/student/auth-session?action=sign',
    category: 'Direct IP Server / No Domain Verification',
  },
  {
    id: 'url_shortener',
    label: 'Obfuscated Short URL (bit.ly)',
    url: 'https://bit.ly/claim-student-grant-2026',
    category: 'Masked Destination / URL Shortener',
  },
  {
    id: 'url_legitimate',
    label: 'Legitimate College Portal (.ac.in)',
    url: 'https://portal.iitb.ac.in/student/notices',
    category: 'Verified Academic Registry (.ac.in) / Multi-Part Suffix',
  },
];
