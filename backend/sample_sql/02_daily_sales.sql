CREATE TABLE daily_sales AS
SELECT order_id, total_amount
FROM staging_orders;
