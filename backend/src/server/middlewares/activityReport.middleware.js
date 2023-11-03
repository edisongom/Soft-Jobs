const activityReport = (req, _, next) => {
  const activity = {
    Report: 'User Activity App',
    OriginalUrl: req.originalUrl,
    Method: req.method,
    Path: req.path,
    Params: req.params,
    QueryParams: req.query
  }
  next()
  return console.log(activity)
}

module.exports = {
  activityReport
}
