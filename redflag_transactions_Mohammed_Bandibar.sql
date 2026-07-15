-- ======================================================================
 -- RedFlag — Fraud Detection Submission 
 -- Student: Mohammed Bandibar  |  Batch: DA-DS-1
 -- ===================================================================== 
CREATE DATABASE redflag;
USE redflag;
select count(*) from redflag.transactions;
select count(distinct user_id) from redflag.transactions;
select min(txn_time),max(txn_time) from redflag.transactions;

-- ====================================================================
-- pattern1.Velocity Fraud
-- What I'm looking for: users with 30+ transactions in a single day —
-- signature of automated bots, account takeover, or merchant churning
-- Expected suspects: ~45-55 user-days
-- ====================================================================

select user_id,date(txn_time) as attack_date ,count(*) as daily_txn_count
from transactions
group by user_id,date(txn_time)
having count(*) >=30
order by daily_txn_count desc;

-- My findings: 50 suspect user-days flagged.
-- Top offenders: user <id> on <date> with <count> txns, ...

-- ========================================================================
-- Pattern2·Round-Amount Clustering 
-- What I'm looking for: users with 15+ transactions at exact round amounts
-- (100, 200, 500, 1000, 2000, 5000, 10000) — signature of money laundering
-- =========================================================================

select user_id,count(*) as round_txn_count 
from transactions
where amount in(100,200,500,1000,2000,5000,10000)
group by user_id
having count(*) >=15
order by round_txn_count desc;

-- My findings: 25 suspect users flagged.
-- Top offenders: user <id> with <count> round-amount txns, user <id> with <count>, ..

--  ==================================================================================
-- Pattern3·Card Testing 
-- What I'm looking for: users with 30+ transactions under ₹10 in a
-- single day — signature of testing stolen card dumps for validity
--  ==================================================================================

select user_id ,date (txn_time) as attack_date ,count(*) as  daily_txn_count
from transactions
where amount < 10
group by user_id,date(txn_time)
having count(*) >=30
order by daily_txn_count desc;

-- My findings: 20  suspect user-days flagged.
-- Top offenders: user <id> on <date> with <count> sub-₹10 txns,
-- user <id> on <date> with <count>, ...

-- =====================================================================================
-- Pattern4·Failed-Then-Succeeded 
-- What I'm looking for: users with 20+ FAILED transactions — signature
-- of card-testing scripts retrying stolen card/CVV combos
-- =====================================================================================

select user_id,count(*) as txn_status from transactions
where status = 'FAILED'
group by user_id
having count(*) >= 20
order by txn_status desc;

-- My findings: 25 suspect users flagged.
-- Top offenders: user <id> with <count> failures, user <id> with <count>, ..

-- ====================================================================================
-- Pattern 5·Odd-Hour Concentration 
-- What I'm looking for: users where 80%+ of transactions occur between
-- 2 AM and 4 AM, with 30+ total transactions — signature of automated
-- bot scripts running outside normal Indian business hours
-- ====================================================================================

select user_id ,count(*) as total_txns,
sum(case when hour(txn_time) between 2 and 4 then 1 else 0 end)
as odd_hour_count from transactions
group by user_id
having total_txns >=30 and 
odd_hour_count/total_txns >=0.8;

-- My findings: 20 suspect users flagged.
-- Top offenders: user <id> with <total> total txns, <count> in odd hours, ...


-- ==================================================================================
-- Pattern6·Mule Accounts 
-- What I'm looking for: users with 5+ instances where a CREDIT
-- transaction is followed within 30 minutes by a DEBIT of at least
-- 70% of the credited amount — signature of a mule account rapidly
-- moving stolen funds out after receiving them
-- ==================================================================================

select c.user_id,count(*) as suspicious_credit_count
from transactions c
where c.txn_type ='CREDIT'
and exists
(select 1 from transactions d 
where d.user_id = c.user_id
and d.txn_type = 'DEBIT'
and timestampdiff(minute , c.txn_time ,d.txn_time) between 0 and 30 
and d.amount >= c.amount*0.7)
group by c.user_id
having count(*) >=5
order by suspicious_credit_count desc;

-- My findings: 30 suspect users flagged.
-- Top offenders: user <id> with <count> suspicious CREDIT-DEBIT pairs, ..


-- =================================================================================
--  Pattern 7·Refund Abuse  
-- What I'm looking for: users with 20+ total transactions where the
-- refund ratio (refunds / total) exceeds 40% — signature of chargeback
-- fraud or merchant loophole exploitation. Real users stay under 5%.
-- =================================================================================


select user_id ,count(*) as total_transaction,
sum(case when txn_type = 'REFUND' then 1 else 0 end) as refund_txn
from transactions
group by user_id
having total_transaction >= 20
and
refund_txn/total_transaction >0.4
order by refund_txn/total_transaction desc;

-- My findings: 24 suspect users flagged.
-- Top offenders: user <id> with <refund_txn>/<total_transaction> refund ratio, ...

-- =================================================================================
-- Pattern 8·Merchant Collusion 
-- What I'm looking for: merchants where the top 5 customers by spend
-- account for more than 60% of the merchant's total transaction volume
-- — signature of a merchant colluding with a small ring to launder
-- money, rather than serving a genuine broad customer base
-- =================================================================================

with user_merchant_spend as(select merchant_id,user_id,sum(amount) as total_amount 
from transactions
group by merchant_id,user_id),
ranked_spend as(
select merchant_id,user_id,total_amount,row_number() over
(partition by merchant_id order by total_amount desc) as spend_rank,
sum(total_amount) over(partition by merchant_id) as merchant_grand_total
from user_merchant_spend),
top5_summary as(
select merchant_id,sum(total_amount) as top5_spend,
max(merchant_grand_total) as merchant_total from ranked_spend
where spend_rank <=5
group by merchant_id
)
select merchant_id,top5_spend,merchant_total,top5_spend/merchant_total as
collusion_ratio from top5_summary
where top5_spend/merchant_total > 0.6
order by collusion_ratio desc;

-- My findings: 15 colluding merchants flagged (merchant IDs 1-15).
-- Top offender: merchant 12 with a 99.9% collusion ratio (top 5 customers
-- account for ₹21.75L of ₹21.77L total volume).


-- ============================================================================= 
-- Pattern 9·Just-Under-Threshold 
-- What I'm looking for: users with 10+ transactions at exactly ₹9,999
-- — deliberately staying just under the ₹10,000 KYC threshold to avoid
-- enhanced checks. Classic money-laundering/structuring signature.
-- ============================================================================= 

select user_id,count(*) as fraud_transaction  from transactions
where amount=9999.00 
group by user_id
having fraud_transaction >=10
order by fraud_transaction desc;

-- My findings: 20 suspect users flagged.
-- Top offenders: user <id> with <count> transactions at ₹9,999, ...

-- ==============================================================================
-- Pattern 10·Dormant-Then-Active 
-- What I'm looking for: users with a 90+ day gap between two consecutive
-- transactions, followed by 15+ transactions after that gap — signature
-- of account takeover, where a fraudster gains access to a dormant
-- account (phishing, credential leak, SIM swap) and monetises it fast
-- ==============================================================================

with txn_gaps as(
select user_id,txn_time,
lag(txn_time) over (partition by user_id order by txn_time) as prev_txn_time,
timestampdiff(day,lag(txn_time)over (partition by user_id order by txn_time),
txn_time) as days_gap
from transactions
),
qualifying_gaps as(
select user_id,txn_time as wake_up_time,
row_number() over (partition by user_id order by txn_time desc) as gap_rank
from txn_gaps
where days_gap >=90
),
latest_gap as(select user_id,wake_up_time from qualifying_gaps
where gap_rank =1)
select g.user_id,g.wake_up_time,count(t.txn_id) as post_gap_txn_count
from latest_gap g 
join transactions t
on t.user_id = g.user_id
and t.txn_time >=g.wake_up_time
group by g.user_id,g.wake_up_time
having count(t.txn_id) >=15
order by post_gap_txn_count desc;

-- My findings: 26 suspect users flagged.
-- Top offenders: user <id> woke up on <date> with <count> transactions
-- following their dormancy period, ...

-- ==============================================================================
-- Pattern 11 · Velocity Spike
-- What I'm looking for: users whose peak monthly transaction count is
-- at least 5x their average monthly count (peak >= 20), active in more
-- than 1 month — signature of abrupt behavioural change, almost always
-- indicating account takeover. The ML-free equivalent of anomaly
-- detection.
-- Expected suspects: 35-45
-- =====================================================================

with monthly_counts as (select user_id,date_format(txn_time,'%Y-%m') as txn_month,
count(*) as monthly_txn_count from transactions
group by user_id,date_format(txn_time,'%Y-%m')
),
user_stats as(
select user_id,txn_month,monthly_txn_count,
sum(monthly_txn_count) over (partition by user_id) /6 as avg_monthly_txn,
max(monthly_txn_count) over (partition by user_id) as peak_monthly_txn,
 count(*) over (partition by user_id) as active_months
from monthly_counts
)
select distinct user_id,avg_monthly_txn,peak_monthly_txn,active_months
from user_stats
where peak_monthly_txn >= 5*avg_monthly_txn
and peak_monthly_txn>=20
and active_months >1
order by peak_monthly_txn desc;

-- My findings: 45 suspect users flagged.
-- Top offenders: user <id> with peak month of <count> txns vs average
-- of <avg>, a <ratio>x spike, ...

-- =======================================================================
-- Pattern 12 · Geographic Impossibility 
 -- What I'm looking for: users with consecutive transactions in two
-- different cities within 60 minutes of each other — physically
-- impossible for one person, almost always indicating account takeover
-- or stolen-card usage across a fraud syndicate
-- Expected suspects: exactly 15
-- =====================================================================
 with city_check as(SELECT user_id, city, txn_time,
       LAG(city) OVER (PARTITION BY user_id ORDER BY txn_time) AS prev_city,
       LAG(txn_time) OVER (PARTITION BY user_id ORDER BY txn_time) AS prev_txn_time
FROM transactions)
SELECT DISTINCT user_id
FROM city_check
WHERE city != prev_city
AND TIMESTAMPDIFF(MINUTE, prev_txn_time, txn_time) <= 60;

-- My findings: 15 suspect users flagged.
-- Top offender: user <id> transacted in <city1> then <city2> just
-- <minutes> minutes apart, ...




 



