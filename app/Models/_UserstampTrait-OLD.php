<?php

// namespace App\Models;

// trait UserstampTrait
// {


//     // Variável para configurar o UserstampTrait
//     protected $userstamps = [
//         // This userstamp should be set when 'creating' event is invoked.
//         'created_by' => [
//             'depends_on_event' => 'creating',
//         ],
//         // This userstamp should be set when 'creating' or 'updating' event is invoked.
//         // This is an example, if a userstamp depends on multiple events
//         'updated_by' => [
//             'depends_on_event' => ['creating', 'updating'],
//         ],
//         'deleted_by' => [
//             'depends_on_event' => 'deleting',
//         ],

//         // This userstamp should be set if "is_archived" is dirty (has some change in value)
//         'archived_by' => [
//             'depends_on_field' => 'is_archived'
//         ],

//         // This userstamp should be set if "updating" event is invoked on this model,
//         // and "is_submitted" is dirty (has some change in value)
//         'submitted_by' => [
//             'depends_on_event' => 'updating',
//             'depends_on_field' => 'is_submitted'
//         ],

//         // This userstamp should be set if "updating" event is invoked on this model,
//         // and provided expression evaluates to true
//         'suspended_by' => [
//             'depends_on_event' => 'updating',
//             'depends_on_expression' => '$api_hits > 100' // $api_hits is a model field i.e $model->api_hits
//         ],
//     ];

//     // Contains the userstamp fields which depend on a model event
//     // Contains the userstamp fields which depends upon certain expressions
//     // Contains the userstamp fields which depend on a some other field ( which should be dirty in this case )
//     private $userstampsToInsert = [];
//     // events to capture
//     protected static $CREATING = 'creating';
//     protected static $SAVING = 'saving';
//     protected static $UPDATING = 'updating';
//     protected static $DELETING = 'deleting';
//     public static function bootUserStampTrait()
//     {
//         $self = new static();
//         static::creating(function ($model) use ($self) {
//             $self->setUserstampOnModel($model, self::$CREATING);
//         });
//         static::updating(function ($model) use ($self) {
//             $self->setUserstampOnModel($model, self::$UPDATING);
//         });
//         static::saving(function ($model) use ($self) {
//             if (!empty($model->id)) {
//                 $self->setUserstampOnModel($model, self::$SAVING);
//             }
//         });
//         static::deleting(function ($model) use ($self) {
//             $self->setUserstampOnModel($model, self::$DELETING);
//         });
//     }
//     /**
//      * Set userstamp on the current model depending upon the
//      * 1. Event
//      * 2. Field
//      * 3. Expression
//      * @param $model
//      * @param string $eventName
//      */
//     public function setUserstampOnModel(&$model, $eventName = '')
//     {
//         $loggedInUserId = auth()->id();
//         if (!empty($this->userstamps)) {
//             foreach ($this->userstamps as $fieldName => $userstamp) {
//                 if (is_array($userstamp) && count($userstamp) > 0) {
//                     if (count($userstamp) == 1 && $this->dependsOnEvent($userstamp, $eventName)) {
//                         $model->{$fieldName} = $loggedInUserId;
//                     } else {
//                         // check if no event specified along with field name
//                         // or if event is specified then it should match the type event invoked
//                         $isEventMatched = empty($userstamp['depends_on_event']) || $this->dependsOnEvent($userstamp, $eventName);
//                         if ($isEventMatched) {
//                             $isFieldDirty = false;
//                             if (!empty($userstamp['depends_on_field'])) {
//                                 $isFieldDirty = $model->isDirty($userstamp['depends_on_field']);
//                             }
//                             $isExpressionTrue = false;
//                             if (!empty($userstamp['depends_on_expression'])) {
//                                 $expression = $userstamp['depends_on_expression'];
//                                 $pattern = '/\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)/';
//                                 $matchCount = preg_match_all($pattern, $expression, $matches);
//                                 for ($i = 0; $i < $matchCount; $i++) {
//                                     $expression = str_replace($matches[0][$i], '"' . (empty($model->{$matches[1][$i]}) ? null : $model->{$matches[1][$i]}) . '"', $expression);
//                                 }
//                                 $expression = "return " . $expression . ";";
//                                 $isExpressionTrue = eval($expression);
//                             }
//                             if (!empty($userstamp['depends_on_expression']) && !empty($userstamp['depends_on_field'])) {
//                                 if ($isFieldDirty && $isExpressionTrue) {
//                                     $model->{$fieldName} = $loggedInUserId;
//                                 }
//                             } elseif ($isFieldDirty || $isExpressionTrue) {
//                                 $model->{$fieldName} = $loggedInUserId;
//                             }
//                         }
//                     }
//                     // In case of a model, which is being soft deleted, we need to save it with applied userstamp before proceeding.
//                     if ($eventName == self::$DELETING && $this->isSoftDeleteEnabled() && !empty($model->{$fieldName})) {
//                         $model->save();
//                     }
//                 }
//             }
//         }
//     }
//     public function isSoftDeleteEnabled()
//     {
//         // ... check if 'this' model uses the soft deletes trait
//         return in_array('Illuminate\Database\Eloquent\SoftDeletes', class_uses($this)) && !$this->forceDeleting;
//     }
//     /***
//      * Get userstamp field names from the userstamp array
//      * @return mixed
//      */
//     public function getUserstampFields()
//     {
//         return collect($this->userstamps)->map(function ($v, $k) {
//             return is_array($v) ? $k : $v;
//         })->values()->toArray();
//     }
//     /**
//      * Create a relation name from the given userstamp field name
//      * @param $userstamp
//      * @return string
//      */
//     protected function getRelationName($userstamp)
//     {
//         return lcfirst(join(array_map('ucfirst', explode('_', $userstamp))));
//     }
//     /**
//      * Override the default __call() method for query builder
//      * It dynamically handle calls into the query instance.
//      *
//      * @param string $method
//      * @param array $parameters
//      * @return mixed
//      */
//     public function __call($method, $parameters)
//     {
//         if ($method == 'hydrate' && !empty($this->userstamps)) {
//             if (count($parameters) > 0) {
//                 $userstampFields = $this->getUserstampFields();
//                 // get users ids
//                 $userIds = collect($parameters[0])->flatMap(function ($parameter) use ($userstampFields) {
//                     $ustamps = [];
//                     foreach ($userstampFields as $userstamp) {
//                         if (!empty($parameter->{$userstamp})) {
//                             $ustamps[] = $parameter->{$userstamp};
//                         }
//                     }
//                     return $ustamps;
//                 })->unique()->toArray();
//                 $users = $this->getUserModel()->whereIn($this->primaryKey, $userIds)->get();
//                 // associate users with relavent fields
//                 collect($parameters[0])->each(function ($parameter) use ($users, $userstampFields) {
//                     foreach ($userstampFields as $userstamp) {
//                         if (!empty($parameter->{$userstamp})) {
//                             // Find the match from user models
//                             $s = $users->where($this->primaryKey, $parameter->{$userstamp})->first();
//                             $parameter->{$this->getRelationName($userstamp)} = $s;
//                         }
//                     }
//                 });
//             }
//         }
//         if (method_exists($this, '__callAfter')) {
//             return $this->__callAfter($method, $parameters);
//         }
//         // Keep ownder's  ancestor functional
//         if (method_exists(parent::class, '__call')) {
//             return parent::__call($method, $parameters);
//         }
//         throw new BadMethodCallException('Method ' . static::class . '::' . $method . '() not found');
//     }
//     /**
//      * Get the class being used to provide a User.
//      *
//      * @return string
//      */
//     protected function getUserClass()
//     {
//         if (get_class(auth()) === 'Illuminate\Auth\Guard') {
//             return auth()->getProvider()->getModel();
//         }
//         return auth()->guard()->getProvider()->getModel();
//     }
//     /**
//      * Get user model which is being used for auth
//      * @return \Illuminate\Foundation\Application|mixed
//      */
//     protected function getUserModel()
//     {
//         $userModel = app($this->getUserClass());
//         // Disabled userstamps to avoid recursive calls
//         // when the trait is applied on user model itself
//         $userModel->userstamps = [];
//         return $userModel;
//     }
//     /**
//      * Check if given userstamp depends on certain event
//      * @param $userstamp
//      * @param $eventName
//      * @return bool
//      */
//     private function dependsOnEvent($userstamp, $eventName)
//     {
//         if (empty($userstamp['depends_on_event'])) {
//             return false;
//         }
//         // if userstamp depends on one or more than one events, i.e provided in array format
//         if (is_array($userstamp['depends_on_event'])) {
//             return in_array($eventName, $userstamp['depends_on_event']);
//         }
//         // if userstamp depends on only one event, provides as string
//         return $userstamp['depends_on_event'] == $eventName;
//     }
// }
