CREATE TABLE staging_orders AS
SELECT order_id, customer_id, total_amount
FROM raw_orders;
